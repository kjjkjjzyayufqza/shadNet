// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#include <QDateTime>
#include <QDebug>
#include <QtEndian>
#include "matching.h"
#include "stream_extractor.h"
#include "stun_server.h"

// Must match the client's P2P internal framing (p2p_port.h).
static constexpr uint16_t SIGNALING_VPORT_NBO = 0xFFFF;
static constexpr uint16_t RELAY_VPORT_NBO = 0xFFFC;
static constexpr int VPORT_HEADER_SIZE = 4;

// Relay commands, also from p2p_port.h.
static constexpr uint8_t RELAY_FORWARD = 0x10;
static constexpr uint8_t RELAY_DELIVER = 0x11;
static constexpr int RELAY_HEADER_SIZE = 7; // cmd(1) + addr(4) + port(2)

// STUN commands. 0x01 is the primary ping; 0x03 probes the alternate listener and is answered
// with a tagged echo so one client socket can tell the two replies apart.
static constexpr uint8_t STUN_PING = 0x01;
static constexpr uint8_t STUN_ALT_PING = 0x03;
static constexpr uint8_t STUN_ALT_ECHO = 0x83;
static constexpr int STUN_PING_SIZE = 21; // cmd(1) + online_id(16) + local_ip(4)

// A P2P datagram is a game packet, not a file transfer; anything larger is not ours to carry.
static constexpr int RELAY_MAX_PAYLOAD = 2048;

static QByteArray FrameChannel(uint16_t channelNbo, const QByteArray& payload) {
    QByteArray framed;
    framed.reserve(VPORT_HEADER_SIZE + payload.size());
    framed.append(reinterpret_cast<const char*>(&SIGNALING_VPORT_NBO), 2);
    framed.append(reinterpret_cast<const char*>(&channelNbo), 2);
    framed.append(payload);
    return framed;
}

// Returns the channel and strips the header, or -1 when the datagram is not one of ours.
static int SplitChannel(const QByteArray& data, QByteArray& body) {
    if (data.size() < VPORT_HEADER_SIZE)
        return -1;
    uint16_t src_vp, dst_vp;
    memcpy(&src_vp, data.constData(), 2);
    memcpy(&dst_vp, data.constData() + 2, 2);
    if (src_vp != SIGNALING_VPORT_NBO)
        return -1;
    body = data.mid(VPORT_HEADER_SIZE);
    return dst_vp;
}

static QString NormalizeAddress(const QHostAddress& addr) {
    QString text = addr.toString();
    // Strip the IPv6-mapped prefix a dual-stack socket reports, e.g. "::ffff:192.168.1.1".
    if (text.startsWith("::ffff:"))
        text = text.mid(7);
    return text;
}

StunServer::StunServer(SharedState* shared, QObject* parent)
    : QObject(parent), m_socket(new QUdpSocket(this)), m_shared(shared) {
    connect(m_socket, &QUdpSocket::readyRead, this, &StunServer::OnReadyRead);
}

bool StunServer::Start(const QHostAddress& addr, uint16_t port, uint16_t altPort,
                       bool relayEnabled) {
    if (!m_socket->bind(addr, port)) {
        qCritical() << "STUN UDP bind failed on" << addr.toString() << ":" << port
                    << m_socket->errorString();
        return false;
    }
    m_relayEnabled = relayEnabled;
    qInfo().nospace().noquote() << "STUN UDP listener on: " << addr.toString() << ":" << port
                                << (relayEnabled ? " (relay enabled)" : " (relay disabled)");

    if (altPort != 0 && altPort != port) {
        m_altSocket = new QUdpSocket(this);
        connect(m_altSocket, &QUdpSocket::readyRead, this, &StunServer::OnAltReadyRead);
        if (m_altSocket->bind(addr, altPort)) {
            m_altPort = altPort;
            qInfo().nospace().noquote() << "STUN alternate listener on: " << addr.toString() << ":"
                                        << altPort << " (used to classify client NAT types)";
        } else {
            qWarning() << "STUN alternate UDP bind failed on" << altPort
                       << m_altSocket->errorString() << "- NAT types will stay undetermined";
            delete m_altSocket;
            m_altSocket = nullptr;
        }
    } else if (altPort == port) {
        qWarning() << "StunAltPort equals MatchingUdpPort; NAT classification needs two distinct "
                      "ports and stays disabled";
    }
    return true;
}

void StunServer::OnReadyRead() {
    while (m_socket->hasPendingDatagrams()) {
        QByteArray raw;
        raw.resize(static_cast<int>(m_socket->pendingDatagramSize()));
        QHostAddress sender;
        uint16_t senderPort = 0;
        m_socket->readDatagram(raw.data(), raw.size(), &sender, &senderPort);
        if (raw.isEmpty())
            continue;

        QByteArray body;
        const int channel = SplitChannel(raw, body);
        if (channel < 0 || body.isEmpty())
            continue;

        if (static_cast<uint16_t>(channel) == RELAY_VPORT_NBO) {
            HandleRelayForward(body, sender, senderPort);
            continue;
        }
        if (static_cast<uint16_t>(channel) != SIGNALING_VPORT_NBO)
            continue;
        if (static_cast<uint8_t>(body[0]) == STUN_PING)
            HandleStunPing(body, sender, senderPort, false);
    }
}

void StunServer::OnAltReadyRead() {
    while (m_altSocket->hasPendingDatagrams()) {
        QByteArray raw;
        raw.resize(static_cast<int>(m_altSocket->pendingDatagramSize()));
        QHostAddress sender;
        uint16_t senderPort = 0;
        m_altSocket->readDatagram(raw.data(), raw.size(), &sender, &senderPort);
        if (raw.isEmpty())
            continue;

        QByteArray body;
        const int channel = SplitChannel(raw, body);
        if (channel < 0 || body.isEmpty())
            continue;
        if (static_cast<uint16_t>(channel) != SIGNALING_VPORT_NBO)
            continue;
        if (static_cast<uint8_t>(body[0]) == STUN_ALT_PING)
            HandleStunPing(body, sender, senderPort, true);
    }
}

void StunServer::HandleStunPing(const QByteArray& data, const QHostAddress& sender,
                                uint16_t senderPort, bool alternate) {
    if (data.size() < STUN_PING_SIZE)
        return;

    QByteArray rawId = data.mid(1, 16);
    const int nullPos = rawId.indexOf('\0');
    const QString npid = QString::fromUtf8(rawId.left(nullPos >= 0 ? nullPos : 16)).trimmed();
    if (npid.isEmpty())
        return;

    const QString extIpStr = NormalizeAddress(sender);
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    bool changed = false;
    uint8_t natType = 0;
    uint16_t primaryPort = 0;
    {
        QWriteLocker lk(&m_shared->matching.udpLock);
        UdpEndpoint& ep = m_shared->matching.udpExt[npid];
        if (alternate) {
            ep.altPort = senderPort;
        } else {
            changed = ep.addr != extIpStr || ep.port != senderPort;
            ep.addr = extIpStr;
            ep.port = senderPort;
        }
        ep.lastSeenMs = nowMs;
        // Two observations from two server ports: the same mapping for both means the NAT keeps
        // one binding per socket and a punched hole is reusable; different mappings mean it picks
        // a fresh one per destination, and only the relay can carry that peer's traffic.
        if (ep.port != 0 && ep.altPort != 0) {
            const uint8_t classified = ep.port == ep.altPort ? 2 : 3;
            if (classified != ep.natType) {
                ep.natType = classified;
                changed = true;
            }
        }
        natType = ep.natType;
        primaryPort = ep.port;
    }

    if (changed) {
        qInfo().nospace().noquote()
            << "STUN " << (alternate ? "alt " : "") << "ping: " << npid << " ext=" << extIpStr
            << ":" << senderPort << " natType=" << natType;
        RefreshRoomMemberEndpoint(npid, extIpStr, primaryPort, natType);
    }

    const QHostAddress extAddr(extIpStr);
    const uint32_t ipNet = qToBigEndian(static_cast<uint32_t>(extAddr.toIPv4Address()));
    const uint16_t portNet = qToBigEndian(senderPort);

    QByteArray response;
    if (alternate)
        response.append(static_cast<char>(STUN_ALT_ECHO));
    response.append(reinterpret_cast<const char*>(&ipNet), 4);
    response.append(reinterpret_cast<const char*>(&portNet), 2);

    QUdpSocket* sock = alternate ? m_altSocket : m_socket;
    if (sock)
        sock->writeDatagram(FrameChannel(SIGNALING_VPORT_NBO, response), sender, senderPort);
}

bool StunServer::IsRegisteredEndpoint(const QString& addr, uint16_t port) const {
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    QReadLocker lk(&m_shared->matching.udpLock);
    for (auto it = m_shared->matching.udpExt.constBegin();
         it != m_shared->matching.udpExt.constEnd(); ++it) {
        if (it.value().port == port && it.value().addr == addr &&
            it.value().IsFresh(nowMs, UDP_ENDPOINT_TTL_MS))
            return true;
    }
    return false;
}

void StunServer::HandleRelayForward(const QByteArray& body, const QHostAddress& sender,
                                    uint16_t senderPort) {
    if (!m_relayEnabled)
        return;
    if (body.size() <= RELAY_HEADER_SIZE || static_cast<uint8_t>(body[0]) != RELAY_FORWARD)
        return;
    if (body.size() - RELAY_HEADER_SIZE > RELAY_MAX_PAYLOAD) {
        qWarning() << "Relay: oversized datagram from" << sender.toString() << body.size();
        return;
    }

    uint32_t dstIpNet = 0;
    uint16_t dstPortNet = 0;
    memcpy(&dstIpNet, body.constData() + 1, 4);
    memcpy(&dstPortNet, body.constData() + 5, 2);
    const QHostAddress dstAddr(qFromBigEndian(dstIpNet));
    const uint16_t dstPort = qFromBigEndian(dstPortNet);

    // Both ends must be endpoints this server currently sees pinging it. Without that check the
    // relay is an open UDP reflector that anyone can aim at any host on the internet.
    const QString srcIpStr = NormalizeAddress(sender);
    if (!IsRegisteredEndpoint(srcIpStr, senderPort)) {
        qWarning().nospace().noquote() << "Relay: refusing traffic from unregistered endpoint "
                                       << srcIpStr << ":" << senderPort;
        return;
    }
    if (!IsRegisteredEndpoint(dstAddr.toString(), dstPort)) {
        qWarning().nospace().noquote() << "Relay: refusing traffic to unregistered endpoint "
                                       << dstAddr.toString() << ":" << dstPort;
        return;
    }

    const uint32_t srcIpNet = qToBigEndian(static_cast<uint32_t>(sender.toIPv4Address()));
    const uint16_t srcPortNet = qToBigEndian(senderPort);

    QByteArray out;
    out.reserve(RELAY_HEADER_SIZE + body.size() - RELAY_HEADER_SIZE);
    out.append(static_cast<char>(RELAY_DELIVER));
    out.append(reinterpret_cast<const char*>(&srcIpNet), 4);
    out.append(reinterpret_cast<const char*>(&srcPortNet), 2);
    out.append(body.constData() + RELAY_HEADER_SIZE, body.size() - RELAY_HEADER_SIZE);

    m_socket->writeDatagram(FrameChannel(RELAY_VPORT_NBO, out), dstAddr, dstPort);
}

void StunServer::RefreshRoomMemberEndpoint(const QString& npid, const QString& addr, uint16_t port,
                                           uint8_t natType) {
    if (port == 0)
        return;
    QWriteLocker lk(&m_shared->matching.roomsLock);
    for (auto it = m_shared->matching.rooms.begin(); it != m_shared->matching.rooms.end(); ++it) {
        RoomMember* member = it.value().findByNpidMut(npid);
        if (!member || (member->addr == addr && member->port == port))
            continue;
        qInfo().nospace().noquote() << "Room " << it.key().second << ": member " << npid
                                    << " endpoint updated to " << addr << ":" << port;
        member->addr = addr;
        member->port = port;
        member->natType = natType;
    }
}
