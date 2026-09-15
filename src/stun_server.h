// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QHostAddress>
#include <QObject>
#include <QUdpSocket>
#include "client_session.h"

/// UDP side of matchmaking.
///
/// Three jobs share one port because clients multiplex all of them onto the single socket their
/// P2P traffic uses, which is what makes the endpoint the server observes the endpoint peers can
/// actually reach:
///   * STUN - tell a client the address and port this server sees it on.
///   * NAT classification - a second listener on another port gives the second observation needed
///     to tell an endpoint-independent mapping from a per-destination one.
///   * Relay - forward datagrams between two registered endpoints for peers that cannot punch a
///     hole directly. Both ends keep their mapping alive with their STUN pings, so the server can
///     always reach them even when they cannot reach each other.
class StunServer : public QObject {
    Q_OBJECT
public:
    explicit StunServer(SharedState* shared, QObject* parent = nullptr);

    /// Binds the primary listener. `altPort` of 0 leaves NAT classification unavailable.
    bool Start(const QHostAddress& addr, uint16_t port, uint16_t altPort, bool relayEnabled);

    uint16_t AltPort() const {
        return m_altPort;
    }
    bool RelayEnabled() const {
        return m_relayEnabled;
    }

private slots:
    void OnReadyRead();
    void OnAltReadyRead();

private:
    void HandleStunPing(const QByteArray& data, const QHostAddress& sender, uint16_t senderPort,
                        bool alternate);
    void HandleRelayForward(const QByteArray& body, const QHostAddress& sender,
                            uint16_t senderPort);
    /// Copies a refreshed endpoint into every room record that still carries the old one, so a
    /// member that registered late is not stuck with a portless entry for the life of the room.
    void RefreshRoomMemberEndpoint(const QString& npid, const QString& addr, uint16_t port,
                                   uint8_t natType);
    /// True when `addr`:`port` is the endpoint a signed-in account currently pings us from.
    bool IsRegisteredEndpoint(const QString& addr, uint16_t port) const;

    QUdpSocket* m_socket;
    QUdpSocket* m_altSocket = nullptr;
    SharedState* m_shared;
    uint16_t m_altPort = 0;
    bool m_relayEnabled = false;
};
