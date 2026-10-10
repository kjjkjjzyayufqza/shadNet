// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#include <functional>
#include <QDateTime>
#include <QDebug>
#include <QVector>
#include "client_session.h"
#include "proto_utils.h"
#include "shadnet.pb.h"

namespace {

// libSceNpManager's send path refuses a payload outside 1..512 bytes (the size field of the
// message structure is bounds-checked before anything is queued), so anything else on the wire
// did not come from the retail library.
constexpr int IGM_MAX_PAYLOAD = 512;

// One send names a handful of players - a lobby's worth at most. A request naming far more is
// either a broken caller or someone using the relay as a broadcast channel.
constexpr int IGM_MAX_TARGETS = 16;

// Budget per session. The titles this serves use in-game messages for invites and join-in
// requests, which are user-initiated and arrive at human speed; this leaves room for a burst
// while keeping a stuck retry loop from becoming a flood.
constexpr int IGM_WINDOW_MS = 10'000;
constexpr int IGM_MAX_PER_WINDOW = 30;

} // namespace

// SendInGameMessage (command 42).
//
// The server-side half of libSceNpManager's sceNpInGameMessageSendDataA: a short title-defined
// payload delivered to named accounts without going through the room or the P2P mesh. Titles use
// it for invites, join-in requests and cross-room notices, which is why the emulator's previous
// behaviour - a generic stub returning success - produced interactions that reported "sent" and
// then silently never happened.
ErrorType ClientSession::CmdSendInGameMessage(StreamExtractor& data, QByteArray& reply) {
    shadnet::SendInGameMessageRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    const int payloadSize = static_cast<int>(req.message().size());
    if (payloadSize <= 0 || payloadSize > IGM_MAX_PAYLOAD) {
        qWarning() << "SendInGameMessage:" << m_info.npid << "payload" << payloadSize
                   << "outside 1.." << IGM_MAX_PAYLOAD;
        return ErrorType::TooLarge;
    }
    if (req.target_account_ids_size() <= 0) {
        return ErrorType::InvalidInput;
    }
    if (req.target_account_ids_size() > IGM_MAX_TARGETS) {
        qWarning() << "SendInGameMessage:" << m_info.npid << "named"
                   << req.target_account_ids_size() << "targets, max" << IGM_MAX_TARGETS;
        return ErrorType::InvalidInput;
    }

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    if (nowMs - m_igmWindowStartMs >= IGM_WINDOW_MS) {
        m_igmWindowStartMs = nowMs;
        m_igmSentInWindow = 0;
    }
    if (m_igmSentInWindow >= IGM_MAX_PER_WINDOW) {
        qWarning() << "SendInGameMessage:" << m_info.npid << "rate limited (" << m_igmSentInWindow
                   << "in" << IGM_WINDOW_MS << "ms)";
        return ErrorType::RateLimited;
    }
    ++m_igmSentInWindow;

    // Delivery is scoped to the sender's own title group. An in-game message is title-defined
    // bytes; handing them to a session running a different game means that game parses a payload
    // it never agreed a format for.
    QString senderGroup;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        senderGroup = m_shared->matching.titleGroups.value(m_matching.titleId, m_matching.titleId);
    }

    // Delivered as an NP WebApi push event, which is how the retail stack does it:
    // libSceNpManager's send path hands the payload to the WebApi layer with the data type
    // "inGameMessage" (module offset 0x34B0 passes that literal), and the receiving title picks
    // it up through its registered push-event callback. There is no receive entry point in
    // libSceNpManager at all, so this is the only channel the API can have used.
    const QByteArray body(req.message().data(), payloadSize);
    const QList<QPair<QString, QString>> extd = {
        {QStringLiteral("messageType"), QString::number(req.message_type())},
        {QStringLiteral("fromAccountId"), QString::number(m_info.userId)},
    };

    // Recipients are resolved under the locks and written to outside them, the way every other
    // fan-out on this server does it: send() reaches into a session's write path, and holding a
    // shared lock across it would let one slow socket stall every room operation. The locks are
    // also taken rooms-then-clients, matching NotifyRoomMembers, so two fan-outs running at once
    // cannot take them in opposite orders.
    struct Target {
        QString npid;
        std::function<void(QByteArray)> send;
    };
    QVector<Target> reachable;
    shadnet::SendInGameMessageReply rep;
    {
        QReadLocker roomLk(&m_shared->matching.roomsLock);
        QReadLocker lk(&m_shared->clientsLock);
        for (int i = 0; i < req.target_account_ids_size(); ++i) {
            const int64_t targetUserId = static_cast<int64_t>(req.target_account_ids(i));
            auto* result = rep.add_results();
            result->set_account_id(static_cast<uint64_t>(targetUserId));
            result->set_delivered(false);

            auto clientIt = m_shared->clients.find(targetUserId);
            if (clientIt == m_shared->clients.end()) {
                // Offline is a normal outcome, reported per target rather than failing the whole
                // send: a title asking three friends to join expects to hear which ones heard it.
                continue;
            }
            const QString targetTitle = m_shared->lastLoginTitleId.value(targetUserId);
            const QString targetGroup =
                m_shared->matching.titleGroups.value(targetTitle, targetTitle);
            if (targetGroup != senderGroup) {
                qWarning() << "SendInGameMessage:" << m_info.npid << "-> user" << targetUserId
                           << "skipped, title group" << targetGroup << "!=" << senderGroup;
                continue;
            }
            result->set_delivered(true);
            reachable.append({clientIt->npid, clientIt->send});
        }
    }

    for (const Target& target : reachable) {
        target.send(BuildNotification(NotificationType::WebApiPushEvent,
                                      BuildWebApiPushPayload(QStringLiteral("inGameMessage"), 0,
                                                             QStringLiteral("inGameMessage"), body,
                                                             m_info.npid, target.npid, extd)));
    }

    qInfo() << "SendInGameMessage:" << m_info.npid << "type=" << req.message_type()
            << "bytes=" << payloadSize << "targets=" << req.target_account_ids_size()
            << "delivered=" << reachable.size();

    appendProto(reply, rep);
    return ErrorType::NoError;
}
