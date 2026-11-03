/* HKBU BU-Guest captive portal acceptance
 *
 * Sends the terms-acceptance POST request to the HKBU BU-Guest captive
 * portal (https://buguest-portal.hkbu.edu.hk:8003) after the STA has
 * connected to the upstream access point, and refreshes it periodically
 * (a BU-Guest session lasts 12 hours, we re-accept every 6 hours).
 */

#ifndef PORTAL_H
#define PORTAL_H

/* Start the portal acceptance background task. Safe to call once at boot.
 * The task waits for connectivity notifications and posts the terms. */
void portal_init(void);

/* Notify the portal task that the STA just got an IP address.
 * Called from the IP_EVENT_STA_GOT_IP handler. Non-blocking. */
void portal_notify_connected(void);

#endif /* PORTAL_H */
