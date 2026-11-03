/* HKBU BU-Guest captive portal acceptance
 *
 * After the STA has connected to the upstream "BU-Guest" network and
 * received an IP address, this module POSTs the captive-portal terms
 * acceptance form to https://buguest-portal.hkbu.edu.hk:8003/index.php?zone=v986
 * (equivalent to clicking "Connect" on the portal page). The request is
 * repeated every PORTAL_REFRESH_S seconds, since a BU-Guest session
 * expires after 12 hours.
 *
 * TLS: the portal presents a public Sectigo certificate. The Sectigo
 * intermediate and root certificates are bundled below as trust anchors
 * (they are long-lived, unlike the leaf certificate).
 */

#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_http_client.h"

#include "portal.h"

static const char *TAG = "portal";

#define PORTAL_URL "https://buguest-portal.hkbu.edu.hk:8003/index.php?zone=v986"
/* A BU-Guest session lasts 12 hours - re-accept every 6 hours. */
#define PORTAL_REFRESH_S (6 * 3600)
#define PORTAL_TASK_STACK 8192
#define PORTAL_TASK_PRIO 3
#define PORTAL_MAX_ATTEMPTS 10
#define PORTAL_RETRY_DELAY_MS 30000
#define PORTAL_REFRESH_TICKS pdMS_TO_TICKS((uint32_t)PORTAL_REFRESH_S * 1000)
#define PORTAL_FAILURE_RETRY_TICKS pdMS_TO_TICKS(1800 * 1000)

static SemaphoreHandle_t portal_notify_sem;

/* Trust anchors: Sectigo Public Server Authentication CA OV R36 (intermediate)
 * and Sectigo Public Server Authentication Root R46. */
static const char portal_ca_certs[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGTDCCBDSgAwIBAgIQLBo8dulD3d3/GRsxiQrtcTANBgkqhkiG9w0BAQwFADBf\n"
    "MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQD\n"
    "Ey1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYw\n"
    "HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBgMQswCQYDVQQGEwJHQjEY\n"
    "MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFB1Ymxp\n"
    "YyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgT1YgUjM2MIIBojANBgkqhkiG9w0B\n"
    "AQEFAAOCAY8AMIIBigKCAYEApkMtJ3R06jo0fceI0M52B7K+TyMeGcv2BQ5AVc3j\n"
    "lYt76TvHIu/nNe22W/RJXX9rWUD/2GE6GF5x0V4bsY7K3IeJ8E7+KzG/TGboySfD\n"
    "u+F52jqQBbY62ofhYjMeiAbLI02+FqwHeM8uIrUtcX8b2RCxF358TB0NHVccAXZc\n"
    "FYgZndZCeXxjuca7pJJ20LLUnXtgXcjAE1vY4WvbReW0W6mkeZyNGdmpTcFs5Y+s\n"
    "yy6LtE5Zocji9J9NlNnReox2RWVyEXpA1ChZ4gqN+ZpVSIQ0HBorVFbBKyhdZyEX\n"
    "gZgNSNtBRwxqwIzJePJhYd4ZUhO1vk+/uP3nwDk0p95q/j7naXNCSvESnrHPypaB\n"
    "WRK066nKfPRPi9m9kIOhMdYfS8giFRTcdgL24Ycilj7ecAK9Trh0VbjwouJ4WH+x\n"
    "bt47u68ZFCD/ac55I0DNHkCpaPruj6e9Rmr7K46wZDAYXuEAqB7tGG/jd6JAA+H2\n"
    "O44CV98NRsU213f1kScIZntNAgMBAAGjggGBMIIBfTAfBgNVHSMEGDAWgBRWc1hk\n"
    "lfmSGrASKgRieaFAFYghSTAdBgNVHQ4EFgQU42Z0u3BojSxdTg6mSo+bNyKcgpIw\n"
    "DgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYI\n"
    "KwYBBQUHAwEGCCsGAQUFBwMCMBsGA1UdIAQUMBIwBgYEVR0gADAIBgZngQwBAgIw\n"
    "VAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv\n"
    "UHVibGljU2VydmVyQXV0aGVudGljYXRpb25Sb290UjQ2LmNybDCBhAYIKwYBBQUH\n"
    "AQEEeDB2ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3Rp\n"
    "Z29QdWJsaWNTZXJ2ZXJBdXRoZW50aWNhdGlvblJvb3RSNDYucDdjMCMGCCsGAQUF\n"
    "BzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEA\n"
    "BZXWDHWC3cubb/e1I1kzi8lPFiK/ZUoH09ufmVOrc5ObYH/XKkWUexSPqRkwKFKr\n"
    "7r8OuG+p7VNB8rifX6uopqKAgsvZtZsq7iAFw04To6vNcxeBt1Eush3cQ4b8nbQR\n"
    "MQLChgEAqwhuXp9P48T4QEBSksYav7+aFjNySsLYlPzNqVM3RNwvBdvp6vgDtGwc\n"
    "xlKQZVuuNVIaoYyls8swhxDeSHKpRdxRauTLZ+pl+wGvy0pnrLEJGSz9mOEmfbod\n"
    "e/XopR2NGqaHJ6bIjyxPu6UtyQGI26En7UAEozACrHz06Nx2jTAY9E6NeB6XuobE\n"
    "wLK025ZRmvglcURG1BrV24tGHHTgxCe8M3oGlpUSMTKQ2dkgljZVYt+gKdFtWELZ\n"
    "MuRdi+X3XsrR8LFz+aLUiDRfQqhmw3RxjIyVKvvu9UPYY1nsvxYmFnUSeM+2q1z/\n"
    "iPUry+xDY9MC6+IhleKT094VKdFVp7LXH42+wvU+17lRolQ2mK2N/nBLVBwaIhib\n"
    "QXw4VYKwB86Bc6eS6iqsc94KEgD/U4VsjmgfhK+Xp4NM+VYzTTa3QeV3p8xOM0cw\n"
    "q1p8oZFA+OBcz3FYWpDIe5j0NWKlw9hXsTyPY/HeZUV59akskSOSRSmDfe8wJDPX\n"
    "58uB9/7lud0G3x0pxQAcffP0ayKavNwDTw4UfJ34cEw=\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGlTCCBH2gAwIBAgIRANJ/u8HeNZ5SFq1hSVhgmcQwDQYJKoZIhvcNAQEMBQAw\n"
    "gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtK\n"
    "ZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYD\n"
    "VQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIx\n"
    "MDMyMjAwMDAwMFoXDTM4MDExODIzNTk1OVowXzELMAkGA1UEBhMCR0IxGDAWBgNV\n"
    "BAoTD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UEAxMtU2VjdGlnbyBQdWJsaWMgU2Vy\n"
    "dmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOC\n"
    "Ag8AMIICCgKCAgEAk77VNlJ12AEjoBxHQknuY7a3If3EldVIKyZ8FFMQ2nn9K7ct\n"
    "pNQs+uoy3UnCub0PSD17WphUr55dMXRPB/xQId2kz2hPGxJjbSWZTCqZ80gwYfqB\n"
    "fB6nCErcPiscHxhMcao1jK34bug7StnllALWiYQTqm3ITzPMUJY3kjPcX4jnn1TZ\n"
    "SPCYQ9Zm/Z8XOEPFAVEL1+MjDxRdWxTnS77d9MjaAzfR1jmhIVEwg7Bt1zBOlluR\n"
    "8HAkq79FgWRDDb0hOi886Z4NyyC1QifM2m+b7mQwkDnNk2WBITG1I1AzNyLjOO34\n"
    "MTDMRf5i+dFdMnlCh99qzFYZQE3Oqrv5tXZJlPEn+JGlg+UGs2MOgNzgElWApjtm\n"
    "tDmHLcjw0NEU6eQNTQ72XVdyxTscR1ad4tX7gWGMzE2AkDRbt9cUddzYBEifwMEo\n"
    "iLTpHMqnsfFWt3tJTFnlIBWohAIp+jiUaZpJBo/NH3kUFxIMg3reH7GX7vmXeCik\n"
    "yESS6X0mBaZYcpt5E9gRX67FOGI0aLKGMI74kGGeMmz1BzbNokxu7Io27fLmmRVE\n"
    "cMN8vJw5wLTha/eDJSNX2RKA5UnwdQ/vjescm1QotCE8/HwK/+97a3X/ix2gGQWr\n"
    "+vgrgULoOLq7+6r9PeDzyt9Ol5cp7fMYVumllqy9w5CYsuD5otSmR0N8bc8CAwEA\n"
    "AaOCASAwggEcMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1Ud\n"
    "DgQWBBRWc1hklfmSGrASKgRieaFAFYghSTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0T\n"
    "AQH/BAUwAwEB/zAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEQYDVR0g\n"
    "BAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRy\n"
    "dXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDA1\n"
    "BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVz\n"
    "dC5jb20wDQYJKoZIhvcNAQEMBQADggIBADpvBIlq7bMU0cFDT/9P9+BsgCkRgQs0\n"
    "S6Bf7vJSlWMHwby0VGvxCS0hrbi0K2BINZbEbsVsgpQq04431yyoVn3Hldorgq24\n"
    "RldRDOOipEZDTFB9wC9HYt1thHF00XeG2C8KC1plwoEzKAIhPvefI/C3cT0CfTXJ\n"
    "uFjUbKIgSwjNjw6YHtLgoy/hd5+JLUlLco/gzFX/qWbT7tEquOMYpsNKWZj8TLqP\n"
    "q6zMiG4Na6feEZte6YPXGrMWlTWN341vDedc+yxQqSug79HJUQcOZs7KyDWztmae\n"
    "QxsPE49UV/8XwrfZtZaYyrs4FpD94Z4Q8dzXGL8+qEJjxgcza7W6PROaClubavd1\n"
    "VKPm8+aCW77u7SxpR2TFGL6kPdxsKyFijpcunR5V79sUyROfNdzjrAcFWZXK8sbb\n"
    "9FlnwuVG677JLv+ZVTX5AxLvW5OB4zt5uS+zB62wJ/Wv+jXGAttSAcJec4iFgCWH\n"
    "Rvdi/jJoSzRLa3nEzx6pFIzclSCnh0u1xCeLcUBypSiPga8W+6PkuoyQq8U9qs9E\n"
    "oxG5NvrvlyshwUS9yvcZRGw7Ljlx4jJH/BhIPR8kIBCQj1vna9TziZOrw1Of8hDU\n"
    "bHKFG9Pm8Dp2vbjz/2JH39qvxshPKVllGfq+5klPm7yZRUYTiCMAbqwNdL/nsqF2\n"
    "Rnnyp58XRStJ\n"
    "-----END CERTIFICATE-----\n";

/* The captive-portal terms acceptance form, URL-encoded
 * (terms text + redirurl + zone + accept button, as sent by the browser). */
static const char portal_form_body[] =
    "terms=The+use+of+BU-Guest+Wi-Fi+service+is+limited+to+a+maximum+12+hou"
    "rs+per+each+session.+Turn+off+and+on+the+Wi-Fi+to+re-connect+the+porta"
    "l+is+needed.%0D%0A%09%09++%0D%0ABU-Guest+Wi-Fi+Service+provides+%2A%2A"
    "unencrypted%2A%2A+wireless+access+to+the+Internet+that+you+are+solely+"
    "responsible+for+the+security+of+your+system+and+any+transmissions+you+"
    "make+or+receive.+%0D%0AYour+activities+on+the+service+shall+not%3A%0D%"
    "0A-+introduce+any+virus%2C+trojan%2C+worms%2C+time+bomb%2C+cancelbot+o"
    "r+other+programming+routine+that+may+damage+detrimentally+interfere+wi"
    "th%2C+surreptitiously+intercept+or+expropriate+any+system%2C+data+or+p"
    "ersonal+information%3B%0D%0A-+create+any+liability+for+us+or+cause+us+"
    "to+lose+%28in+whole+or+in+part%29+any+of+our+services%3B%0D%0A-+violat"
    "e+any+law%2C+statute%2Cordinance+or+regulation%3B%0D%0A%0D%0AFor+HKBU+"
    "members%2C+please+use+BU-Advanced+or+BU-Standard+instead.%0D%0APlease+"
    "contact+ITO+Hotline+at+34117899+for+details.%0D%0A%09&redirurl=captive"
    "portal-connected.html&zone=v986&accept=Connect";

static bool portal_post_terms(void)
{
    esp_http_client_config_t config = {
        .url = PORTAL_URL,
        .method = HTTP_METHOD_POST,
        .cert_pem = portal_ca_certs,
        .timeout_ms = 15000,
        .keep_alive = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return false;
    }

    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    esp_http_client_set_header(client, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    esp_http_client_set_header(client, "User-Agent", "esp32_nat_router");
    esp_http_client_set_post_field(client, portal_form_body, strlen(portal_form_body));

    bool ok = false;
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        int content_len = esp_http_client_get_content_length(client);
        ESP_LOGI(TAG, "Portal POST: HTTP status %d, content length %d",
                 status, content_len);
        /* The portal answers with a redirect/HTML page on success;
         * any 2xx/3xx is considered accepted. */
        ok = (status >= 200 && status < 400);
    } else {
        ESP_LOGW(TAG, "Portal POST failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return ok;
}

static void portal_task(void *arg)
{
    while (true) {
        /* Wait for the STA to report connectivity (IP_EVENT_STA_GOT_IP). */
        xSemaphoreTake(portal_notify_sem, portMAX_DELAY);
        ESP_LOGI(TAG, "Uplink connected - sending BU-Guest portal acceptance");

        bool accepted = false;
        for (int attempt = 0; attempt < PORTAL_MAX_ATTEMPTS; attempt++) {
            if (portal_post_terms()) {
                accepted = true;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(PORTAL_RETRY_DELAY_MS));
        }

        if (!accepted) {
            ESP_LOGW(TAG, "Portal acceptance failed, will retry on next connect");
            continue;
        }

        /* Keep the session alive: BU-Guest expires after 12 hours, so
         * re-accept every PORTAL_REFRESH_S seconds. A semaphore give means
         * the STA reconnected (DHCP renew / re-association) - re-accept
         * immediately in that case. */
        TickType_t deadline = xTaskGetTickCount() + PORTAL_REFRESH_TICKS;
        while (true) {
            TickType_t now = xTaskGetTickCount();
            TickType_t remaining = (deadline > now) ? (deadline - now) : 1;
            if (xSemaphoreTake(portal_notify_sem, remaining) == pdTRUE) {
                break;  /* reconnected: loop around and re-accept now */
            }
            if (portal_post_terms()) {
                deadline = xTaskGetTickCount() + PORTAL_REFRESH_TICKS;
            } else {
                /* transient failure - retry in 30 min */
                deadline = xTaskGetTickCount() + PORTAL_FAILURE_RETRY_TICKS;
            }
        }
    }
}

void portal_notify_connected(void)
{
    if (portal_notify_sem != NULL) {
        xSemaphoreGive(portal_notify_sem);
    }
}

void portal_init(void)
{
    if (portal_notify_sem == NULL) {
        portal_notify_sem = xSemaphoreCreateBinary();
    }
    xTaskCreate(portal_task, "portal", PORTAL_TASK_STACK, NULL, PORTAL_TASK_PRIO, NULL);
    ESP_LOGI(TAG, "BU-Guest portal acceptance task started");
}
