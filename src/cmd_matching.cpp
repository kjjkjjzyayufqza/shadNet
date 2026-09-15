// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#include <algorithm>
#include <QDateTime>
#include <QDebug>
#include <QHostAddress>
#include <QtEndian>
#include "client_session.h"
#include "proto_utils.h"
#include "shadnet.pb.h"

namespace {

constexpr int32_t MATCHING2_KICKEDOUT_STATUS_CODE = static_cast<int32_t>(0xFF000019u);
constexpr uint32_t MATCHING2_KICKEDOUT_GUARD_VALUE = 4;
constexpr uint8_t MATCHING2_CASTTYPE_BROADCAST = 1;
constexpr uint8_t MATCHING2_CASTTYPE_UNICAST = 2;
constexpr uint8_t MATCHING2_CASTTYPE_MULTICAST = 3;
constexpr uint32_t MATCHING2_ROOM_MSG_EVENT_MESSAGE = 0x2102;

int InternalBinIndexForAttr(uint16_t attrId) {
    if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_1_ID)
        return 0;
    if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_2_ID)
        return 1;
    return -1;
}

int ExternalBinIndexForAttr(uint16_t attrId) {
    if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID)
        return 0;
    if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID)
        return 1;
    return -1;
}

bool AttrWanted(const QVector<uint16_t>& requestedAttrIds, uint16_t attrId) {
    return requestedAttrIds.isEmpty() || requestedAttrIds.contains(attrId);
}

// MBON CreateJoinRoom always passes an 8-byte session-password pointer, often all
// zeros, even for an open player-match room. Join from search leaves the pointer
// null, so a byte-for-byte compare of "8 zeros" vs "empty" rejects a public room.
bool IsBlankRoomPassword(const QByteArray& pw) {
    return pw.isEmpty() ||
           std::all_of(pw.cbegin(), pw.cend(), [](char c) { return c == '\0'; });
}

template <typename Request>
QVector<uint16_t> RequestedAttrIds(const Request& req) {
    QVector<uint16_t> attrIds;
    attrIds.reserve(req.attr_ids_size());
    for (int i = 0; i < req.attr_ids_size(); ++i)
        attrIds.append(static_cast<uint16_t>(req.attr_ids(i)));
    return attrIds;
}

uint64_t MatchingTimestampUsec() {
    return static_cast<uint64_t>(QDateTime::currentDateTimeUtc().toMSecsSinceEpoch()) * 1000ull;
}

bool MatchIntFilter(uint32_t op, uint32_t roomValue, uint32_t filterValue) {
    switch (op) {
    case 1:
        return roomValue == filterValue;
    case 2:
        return roomValue != filterValue;
    case 3:
        return roomValue < filterValue;
    case 4:
        return roomValue <= filterValue;
    case 5:
        return roomValue > filterValue;
    case 6:
        return roomValue >= filterValue;
    default:
        return false;
    }
}

bool RoomMatchesFilters(const Room& room, const shadnet::SearchRoomRequest& req) {
    // Hidden rooms never appear in searches.
    if (room.flagAttr & Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_HIDDEN) {
        qWarning() << "  filter reject HIDDEN: room=" << room.roomId << "flags=" << Qt::hex
                   << room.flagAttr;
        return false;
    }

    // NAT_TYPE_RESTRICTION is ignored in the flag comparison (matches RPCN; it is
    // irrelevant here and breaks some titles' searches).
    const uint32_t nat = Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_NAT_TYPE_RESTRICTION;
    const uint32_t flagFilter = req.flag_filter() & ~nat;
    const uint32_t flagAttr = req.flag_attr() & ~nat;
    if ((room.flagAttr & flagFilter) != flagAttr) {
        qWarning() << "  filter reject FLAG: roomFlags=" << Qt::hex << room.flagAttr
                   << "filter=" << flagFilter << "attr=" << flagAttr;
        return false;
    }

    constexpr uint16_t INT_1 = Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID;
    constexpr uint16_t INT_8 = Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_8_ID;
    for (int i = 0; i < req.int_filters_size(); ++i) {
        const auto& f = req.int_filters(i);
        const uint16_t id = static_cast<uint16_t>(f.attr_id());
        // An empty/unset filter slot (id 0) is sent by some games — skip it.
        if (id == 0)
            continue;
        if (id < INT_1 || id > INT_8) {
            qWarning() << "  filter reject INT id out of range:" << id;
            return false;
        }
        const auto& slot = room.searchIntAttr[id - INT_1];
        if (!MatchIntFilter(f.op(), slot.value, f.attr_value())) {
            qWarning() << "  filter reject INT: id=" << id << "op=" << f.op()
                       << "roomVal=" << slot.value << "set=" << slot.set
                       << "filterVal=" << f.attr_value();
            return false;
        }
    }

    for (int i = 0; i < req.bin_filters_size(); ++i) {
        const auto& f = req.bin_filters(i);
        if (f.attr_id() == 0)
            continue;
        if (static_cast<uint16_t>(f.attr_id()) !=
            Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID) {
            qWarning() << "  filter reject BIN id:" << f.attr_id();
            return false;
        }
        const QByteArray fdata(f.data().data(), static_cast<int>(f.data().size()));
        const bool eq = room.searchBinAttr.data == fdata;
        if ((f.op() == 1 && !eq) || (f.op() == 2 && eq)) {
            qWarning() << "  filter reject BIN: op=" << f.op() << "set=" << room.searchBinAttr.set
                       << "roomLen=" << room.searchBinAttr.data.size()
                       << "filterLen=" << fdata.size();
            return false;
        }
    }
    return true;
}

uint64_t SlotMaskForMaxSlot(uint16_t maxSlot) {
    if (maxSlot >= 64)
        return ~0ull;
    if (maxSlot == 0)
        return 0;
    return (1ull << maxSlot) - 1ull;
}

uint16_t CountSlots(uint64_t mask) {
    uint16_t count = 0;
    while (mask != 0) {
        mask &= mask - 1;
        ++count;
    }
    return count;
}

uint64_t GroupPasswordSlotMask(const Room& room, uint64_t validSlots) {
    uint64_t mask = 0;
    uint16_t slotBase = 0;
    for (const auto& group : room.groups) {
        const uint32_t slotCount = group.slotNum == 0 ? room.maxSlot : group.slotNum;
        for (uint32_t i = 0; i < slotCount && slotBase < room.maxSlot; ++i, ++slotBase) {
            if (group.withPassword)
                mask |= 1ull << slotBase;
        }
        if (slotBase >= room.maxSlot)
            break;
    }
    return mask & validSlots;
}

void RecomputeRoomSlotCounts(Room& room) {
    const uint64_t validSlots = SlotMaskForMaxSlot(room.maxSlot);
    uint64_t privateSlots = room.passwdSlotMask & validSlots;
    if (privateSlots == 0)
        privateSlots = GroupPasswordSlotMask(room, validSlots);

    const uint64_t publicSlots = validSlots & ~privateSlots;
    const uint64_t joinedSlots = room.joinedSlotMask() & validSlots;

    room.publicSlots = CountSlots(publicSlots);
    room.privateSlots = CountSlots(privateSlots);
    room.openPublicSlots = CountSlots(publicSlots & ~joinedSlots);
    room.openPrivateSlots = CountSlots(privateSlots & ~joinedSlots);
}

void ResetLocalMatchingRoomState(MatchingSessionState& matching) {
    matching.roomId = 0;
    matching.myMemberId = 0;
    matching.isRoomOwner = false;
    matching.maxSlots = 0;
    matching.roomFlags = 0;
}

} // namespace

// ── Proto builder helpers ─────────────────────────────────────────────────────

static void FillRoomGroup(shadnet::MatchingRoomGroup* grp, const RoomGroup& g) {
    grp->set_group_id(g.groupId);
    grp->set_has_passwd(g.withPassword);
    grp->set_has_label(g.label.has_value());
    if (g.label.has_value())
        grp->set_label(g.label->constData(), g.label->size());
    grp->set_slot_count(g.slotNum);
    grp->set_num_members(g.numMembers);
}

static shadnet::MatchingRoomDataInternal BuildRoomDataInternal(const Room& room) {
    shadnet::MatchingRoomDataInternal pb;
    pb.set_public_slots(room.publicSlots);
    pb.set_private_slots(room.privateSlots);
    pb.set_open_public_slots(room.openPublicSlots);
    pb.set_open_private_slots(room.openPrivateSlots);
    pb.set_max_slot(room.maxSlot);
    pb.set_server_id(room.serverId);
    pb.set_world_id(room.worldId);
    pb.set_lobby_id(room.lobbyId);
    pb.set_room_id(room.roomId);
    pb.set_passwd_slot_mask(room.passwdSlotMask);
    pb.set_joined_slot_mask(room.joinedSlotMask());
    for (const auto& g : room.groups)
        FillRoomGroup(pb.add_groups(), g);
    pb.set_flags(room.flagAttr);
    for (const auto& slot : room.internalBinAttr) {
        if (!slot.set)
            continue;
        auto* a = pb.add_bin_attrs_internal();
        a->set_attr_id(slot.attrId);
        a->set_data(slot.data.constData(), slot.data.size());
        a->set_update_date(slot.updateDate);
        a->set_update_member_id(slot.updateMemberId);
    }
    return pb;
}

static shadnet::MatchingRoomMemberData BuildRoomMemberData(const RoomMember& member) {
    shadnet::MatchingRoomMemberData pb;
    pb.set_npid(member.npid.toStdString());
    pb.set_member_id(member.memberId);
    pb.set_team_id(member.teamId);
    pb.set_is_owner((member.flagAttr & Matching2::ORBIS_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER) !=
                    0);
    pb.set_join_date(member.joinDate);
    pb.set_nat_type(member.natType);
    pb.set_flag_attr(member.flagAttr);
    pb.set_addr(member.addr.toStdString());
    pb.set_port(member.port);
    pb.set_group_id(member.groupId);
    pb.set_account_id(static_cast<uint64_t>(member.userId));
    pb.set_platform(member.platform);
    if (member.memberBinAttr.set) {
        auto* a = pb.add_bin_attrs_internal();
        a->set_attr_id(member.memberBinAttr.attrId);
        a->set_data(member.memberBinAttr.data.constData(), member.memberBinAttr.data.size());
        a->set_update_date(member.memberBinAttr.updateDate);
    }
    return pb;
}

static shadnet::CreateJoinRoomResponse BuildCreateJoinResponse(const Room& room,
                                                               const RoomMember& me) {
    shadnet::CreateJoinRoomResponse pb;
    *pb.mutable_room_data() = BuildRoomDataInternal(room);
    QList<uint16_t> memberIds = room.members.keys();
    std::sort(memberIds.begin(), memberIds.end());
    for (uint16_t mid : memberIds)
        *pb.add_members() = BuildRoomMemberData(room.members[mid]);
    pb.set_me_member_id(me.memberId);
    pb.set_owner_member_id(room.ownerMemberId);
    return pb;
}

static shadnet::MatchingRoomDataExternal BuildRoomDataExternal(
    const Room& room, const QVector<uint16_t>& requestedAttrIds = {}) {
    shadnet::MatchingRoomDataExternal pb;
    uint16_t memberCount = static_cast<uint16_t>(room.members.size());
    pb.set_max_slot(room.maxSlot);
    pb.set_cur_members(memberCount);
    pb.set_flags(room.flagAttr);
    pb.set_server_id(room.serverId);
    pb.set_world_id(room.worldId);
    pb.set_lobby_id(room.lobbyId);
    pb.set_room_id(room.roomId);
    pb.set_passwd_slot_mask(room.passwdSlotMask);
    pb.set_joined_slot_mask(room.joinedSlotMask());
    pb.set_public_slots(room.publicSlots);
    pb.set_private_slots(room.privateSlots);
    pb.set_open_public_slots(room.openPublicSlots);
    pb.set_open_private_slots(room.openPrivateSlots);
    for (const auto& g : room.groups)
        FillRoomGroup(pb.add_groups(), g);
    for (const auto& slot : room.searchIntAttr) {
        if (!slot.set)
            continue;
        if (!AttrWanted(requestedAttrIds, slot.attrId))
            continue;
        auto* ia = pb.add_external_search_int_attrs();
        ia->set_attr_id(slot.attrId);
        ia->set_attr_value(slot.value);
    }
    if (room.searchBinAttr.set && AttrWanted(requestedAttrIds, room.searchBinAttr.attrId)) {
        auto* ba = pb.add_external_search_bin_attrs();
        ba->set_attr_id(room.searchBinAttr.attrId);
        ba->set_data(room.searchBinAttr.data.constData(), room.searchBinAttr.data.size());
    }
    for (const auto& slot : room.externalBinAttr) {
        if (!slot.set)
            continue;
        if (!AttrWanted(requestedAttrIds, slot.attrId))
            continue;
        auto* ba = pb.add_external_bin_attrs();
        ba->set_attr_id(slot.attrId);
        ba->set_data(slot.data.constData(), slot.data.size());
    }
    const RoomMember* owner = const_cast<Room&>(room).findById(room.ownerMemberId);
    if (owner) {
        pb.set_owner_npid(owner->npid.toStdString());
        pb.set_owner_account_id(static_cast<uint64_t>(owner->userId));
        pb.set_owner_platform(owner->platform);
    }
    return pb;
}

// Build a fully-encoded NotifyRequestEvent payload (u32-LE prefix + proto bytes).
// ── Notification helpers ──────────────────────────────────────────────────────

void ClientSession::SendMatchingNotification(NotificationType type, const QByteArray& payload,
                                             const QString& targetNpid) {
    std::function<void(QByteArray)> sender;
    {
        QReadLocker lk(&m_shared->clientsLock);
        auto userIdIt = m_shared->npidToUserId.find(targetNpid);
        if (userIdIt == m_shared->npidToUserId.end())
            return;
        auto clientIt = m_shared->clients.find(*userIdIt);
        if (clientIt == m_shared->clients.end())
            return;
        sender = clientIt->send;
    }
    sender(BuildNotification(type, payload));
}

void ClientSession::NotifyRoomMembers(NotificationType type, const QByteArray& payload,
                                      const QString& matchingKey, uint64_t roomId,
                                      const QString& excludeNpid) {
    QVector<std::function<void(QByteArray)>> senders;
    {
        QReadLocker roomLk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return;
        QReadLocker clientLk(&m_shared->clientsLock);
        for (const auto& member : roomIt->members) {
            if (member.npid == excludeNpid)
                continue;
            auto userIdIt = m_shared->npidToUserId.find(member.npid);
            if (userIdIt == m_shared->npidToUserId.end())
                continue;
            auto clientIt = m_shared->clients.find(*userIdIt);
            if (clientIt != m_shared->clients.end())
                senders.append(clientIt->send);
        }
    }
    QByteArray pkt = BuildNotification(type, payload);
    for (const auto& send : senders)
        send(pkt);
}

void ClientSession::SendRoomMemberEvent(uint64_t roomId, uint32_t event, uint32_t cause,
                                        const RoomMember& member, const QString& excludeNpid) {
    shadnet::NotifyRoomEvent pb;
    pb.set_ctx_id(m_matching.ctxId);
    pb.set_room_id(roomId);
    pb.set_event(event);
    pb.set_event_cause(cause);
    *pb.mutable_member() = BuildRoomMemberData(member);
    QByteArray payload;
    appendProto(payload, pb);
    NotifyRoomMembers(NotificationType::RoomEvent, payload, m_matching.matchingKey, roomId,
                      excludeNpid);
}

void ClientSession::SendRoomEventToTarget(uint64_t roomId, uint32_t event, uint32_t cause,
                                          int32_t errorCode, const QString& targetNpid) {
    shadnet::NotifyRoomEvent pb;
    pb.set_ctx_id(m_matching.ctxId);
    pb.set_room_id(roomId);
    pb.set_event(event);
    pb.set_event_cause(cause);
    pb.set_error_code(errorCode);
    QByteArray payload;
    appendProto(payload, pb);
    SendMatchingNotification(NotificationType::RoomEvent, payload, targetNpid);
}

uint8_t ClientSession::SelfNatType() const {
    QReadLocker lk(&m_shared->matching.udpLock);
    const auto it = m_shared->matching.udpExt.find(m_info.npid);
    return it == m_shared->matching.udpExt.end() ? 0 : it.value().natType;
}

void ClientSession::GetSelfSignalingAddr(QString& addr, uint16_t& port) const {
    addr.clear();
    port = 0;
    uint8_t natType = 0;
    {
        QReadLocker lk(&m_shared->matching.udpLock);
        auto it = m_shared->matching.udpExt.find(m_info.npid);
        if (it != m_shared->matching.udpExt.end() &&
            it.value().IsFresh(QDateTime::currentMSecsSinceEpoch(), UDP_ENDPOINT_TTL_MS)) {
            addr = it.value().addr;
            port = it.value().port;
            natType = it.value().natType;
        }
    }
    if (port == 0) {
        // Recording the TCP address with no port would look like a usable endpoint to every other
        // member of the room while being unroutable, so the record stays empty and peers fall back
        // to asking for the endpoint once the STUN ping does arrive.
        addr.clear();
        qWarning().nospace().noquote()
            << "No STUN endpoint for " << m_info.npid << " yet (UDP "
            << (m_shared && m_shared->config ? m_shared->config->GetMatchingUdpPort()
                                             : QStringLiteral("?"))
            << " unreachable from this client?); its room record will carry no P2P endpoint";
        return;
    }
    qInfo().nospace().noquote() << "Signaling endpoint for " << m_info.npid << " = " << addr << ":"
                                << port << " natType=" << natType;
}

void ClientSession::ResetMatchingRoomState(uint64_t roomId) {
    if (roomId == 0 || m_matching.roomId != roomId)
        return;
    ResetLocalMatchingRoomState(m_matching);
    qInfo() << "Matching room state reset for" << m_info.npid << "room=" << roomId;
}

ErrorType ClientSession::CmdContextStart(StreamExtractor& data) {
    shadnet::ContextStartRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    m_matching.ctxId = req.ctx_id();
    m_matching.initialized = true;

    qInfo() << "ContextStart:" << m_info.npid << "ctx=" << m_matching.ctxId
            << "title=" << m_matching.titleId << "key=" << m_matching.matchingKey;

    return ErrorType::NoError;
}

ErrorType ClientSession::CmdContextStop(StreamExtractor& data) {
    shadnet::ContextStopRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    m_matching.ctxId = 0;
    m_matching.initialized = false;

    qInfo() << "ContextStop:" << m_info.npid;

    return ErrorType::NoError;
}

ErrorType ClientSession::CmdCreateRoom(StreamExtractor& data, QByteArray& reply) {
    shadnet::CreateRoomRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint16_t maxSlot = static_cast<uint16_t>(req.max_slots());
    if (maxSlot < 1)
        maxSlot = 1;

    uint64_t rid = m_shared->matching.nextRoomId.fetch_add(1);

    Room room;
    room.roomId = rid;
    room.maxSlot = maxSlot;
    room.serverId = m_matching.serverId;
    room.worldId = req.world_id() ? req.world_id() : m_matching.worldId;
    room.lobbyId = req.lobby_id() ? req.lobby_id() : m_matching.lobbyId;
    room.flagAttr = req.flags() & ~Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;
    room.signalingType = static_cast<uint8_t>(req.sig_type());
    room.signalingFlag = static_cast<uint8_t>(req.sig_flag());
    room.signalingHubMemberId = static_cast<uint16_t>(req.sig_main_member());
    for (const auto& id : req.allowed_online_ids())
        room.allowedUsers.append(QString::fromStdString(id));
    for (const auto& id : req.blocked_online_ids())
        room.blockedUsers.append(QString::fromStdString(id));
    for (const auto id : req.allowed_account_ids())
        room.allowedAccountIds.append(static_cast<uint64_t>(id));
    for (const auto id : req.blocked_account_ids())
        room.blockedAccountIds.append(static_cast<uint64_t>(id));

    if (req.room_password_present()) {
        // A room declared password-protected without the bytes to check against would be open to
        // anyone who knows its id, so the request is rejected rather than silently downgraded.
        if (req.room_password().empty())
            return ErrorType::RoomPasswordMissing;
        QByteArray pw(req.room_password().data(), static_cast<int>(req.room_password().size()));
        if (IsBlankRoomPassword(pw)) {
            qInfo() << "CreateRoom: blank session password, treating room as open";
        } else {
            qInfo() << "CreateRoom: session password bytes=" << pw.size();
            room.roomPassword = std::move(pw);
        }
    }
    if (req.has_passwd_slot_mask())
        room.passwdSlotMask = req.passwd_slot_mask();

    const uint32_t groupCount = req.group_configs_size() > 0
                                    ? static_cast<uint32_t>(req.group_configs_size())
                                    : req.group_config_count();
    const QByteArray joinGroupLabel =
        QByteArray(req.join_group_label().data(), static_cast<int>(req.join_group_label().size()));
    for (uint32_t g = 0; g < groupCount; ++g) {
        RoomGroup grp;
        grp.groupId = static_cast<uint8_t>(g + 1);
        if (g < static_cast<uint32_t>(req.group_configs_size())) {
            const auto& cfg = req.group_configs(static_cast<int>(g));
            grp.slotNum = cfg.slot_count();
            grp.withPassword = cfg.has_passwd();
            grp.fixedLabel = cfg.has_label();
            if (cfg.has_label())
                grp.label = QByteArray(cfg.label().data(), static_cast<int>(cfg.label().size()));
        } else {
            grp.withPassword = req.room_password_present();
            grp.fixedLabel = req.join_group_label_present();
            if (!joinGroupLabel.isEmpty())
                grp.label = joinGroupLabel;
        }
        room.groups.append(grp);
    }

    for (int i = 0; i < req.external_search_int_attrs_size(); ++i) {
        const auto& a = req.external_search_int_attrs(i);
        const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
        if (attrId < Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID ||
            attrId > Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_8_ID)
            continue;
        const int idx =
            attrId - Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID;
        room.searchIntAttr[idx].set = true;
        room.searchIntAttr[idx].attrId = attrId;
        room.searchIntAttr[idx].value = a.attr_value();
    }
    RoomMember owner;
    owner.userId = m_info.userId;
    owner.npid = m_info.npid;
    owner.avatarUrl = m_info.avatarUrl;
    GetSelfSignalingAddr(owner.addr, owner.port);
    owner.natType = SelfNatType();
    owner.joinDate = MatchingTimestampUsec();
    owner.teamId = static_cast<uint8_t>(req.team_id());
    owner.flagAttr = Matching2::ORBIS_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER;
    if (!room.groups.isEmpty()) {
        auto groupIt = room.groups.begin();
        if (!joinGroupLabel.isEmpty()) {
            for (auto it = room.groups.begin(); it != room.groups.end(); ++it) {
                if (it->label && *it->label == joinGroupLabel) {
                    groupIt = it;
                    break;
                }
            }
        }
        owner.groupId = groupIt->groupId;
        groupIt->numMembers++;
    }
    if (req.member_bin_attrs_size() > 0) {
        const auto& a = req.member_bin_attrs(0);
        owner.memberBinAttr.set = true;
        owner.memberBinAttr.attrId = static_cast<uint16_t>(a.attr_id());
        owner.memberBinAttr.data = QByteArray(a.data().data(), static_cast<int>(a.data().size()));
        owner.memberBinAttr.updateDate = owner.joinDate;
    }

    RoomMember* member = room.addMember(owner);
    uint16_t memberId = member->memberId;
    room.ownerMemberId = memberId;

    const auto applyCreateBinAttr = [&](const shadnet::MatchingBinAttr& a, const char* source) {
        const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
        const QByteArray attrData(a.data().data(), static_cast<int>(a.data().size()));

        if (const int idx = InternalBinIndexForAttr(attrId); idx >= 0) {
            auto& slot = room.internalBinAttr[idx];
            slot.set = true;
            slot.attrId = attrId;
            slot.data = attrData;
            slot.updateDate = member->joinDate;
            slot.updateMemberId = memberId;
            qInfo() << "CreateRoom: routed bin attr" << Qt::hex << attrId << Qt::dec << "from"
                    << source << "to internal room=" << rid << "bytes=" << slot.data.size();
            return;
        }

        if (const int idx = ExternalBinIndexForAttr(attrId); idx >= 0) {
            auto& slot = room.externalBinAttr[idx];
            slot.set = true;
            slot.attrId = attrId;
            slot.data = attrData;
            qInfo() << "CreateRoom: routed bin attr" << Qt::hex << attrId << Qt::dec << "from"
                    << source << "to external room=" << rid << "bytes=" << slot.data.size();
            return;
        }

        if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID) {
            room.searchBinAttr.set = true;
            room.searchBinAttr.attrId = attrId;
            room.searchBinAttr.data = attrData;
            qInfo() << "CreateRoom: routed bin attr" << Qt::hex << attrId << Qt::dec << "from"
                    << source << "to search external room=" << rid
                    << "bytes=" << room.searchBinAttr.data.size();
            return;
        }

        qWarning() << "CreateRoom: ignored unexpected bin attr" << Qt::hex << attrId << Qt::dec
                   << "from" << source << "room=" << rid << "bytes=" << attrData.size();
    };

    for (int i = 0; i < req.internal_bin_attrs_size(); ++i) {
        applyCreateBinAttr(req.internal_bin_attrs(i), "internal_bin_attrs");
    }
    for (int i = 0; i < req.external_search_bin_attrs_size(); ++i) {
        applyCreateBinAttr(req.external_search_bin_attrs(i), "external_search_bin_attrs");
    }
    for (int i = 0; i < req.external_bin_attrs_size(); ++i) {
        applyCreateBinAttr(req.external_bin_attrs(i), "external_bin_attrs");
    }

    RecomputeRoomSlotCounts(room);

    m_matching.roomId = rid;
    m_matching.myMemberId = memberId;
    m_matching.isRoomOwner = true;
    m_matching.maxSlots = maxSlot;
    m_matching.roomFlags = room.flagAttr;
    m_matching.serverId = room.serverId;
    m_matching.worldId = room.worldId;
    m_matching.lobbyId = room.lobbyId;

    shadnet::CreateRoomReply rep;
    rep.set_room_id(rid);
    rep.set_server_id(room.serverId);
    rep.set_world_id(room.worldId);
    rep.set_lobby_id(room.lobbyId);
    rep.set_member_id(memberId);
    rep.set_max_slots(maxSlot);
    rep.set_flags(room.flagAttr);
    rep.set_cur_members(1);
    *rep.mutable_details() = BuildCreateJoinResponse(room, *member);
    appendProto(reply, rep);

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        const uint32_t worldId = room.worldId;
        const uint64_t lobbyId = room.lobbyId;
        m_shared->matching.rooms.insert({m_matching.matchingKey, rid}, std::move(room));
        if (worldId != 0)
            m_shared->matching.worldRooms[{m_matching.matchingKey, worldId}].append(rid);
        else if (lobbyId != 0)
            m_shared->matching.lobbyRooms[{m_matching.matchingKey, lobbyId}].append(rid);
    }

    qInfo() << "Room" << rid << "created by" << m_info.npid << "max=" << maxSlot
            << "public/open=" << room.publicSlots << "/" << room.openPublicSlots
            << "private/open=" << room.privateSlots << "/" << room.openPrivateSlots
            << "passwdMask=" << Qt::hex << room.passwdSlotMask << "world=" << room.worldId
            << "lobby=" << room.lobbyId << "key=" << m_matching.matchingKey << "flags=" << Qt::hex
            << m_matching.roomFlags << Qt::dec;
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdJoinRoom(StreamExtractor& data, QByteArray& reply) {
    shadnet::JoinRoomRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint64_t roomId = req.room_id();

    uint16_t myMemberId = 0;
    uint16_t maxSlot = 0;

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;
        Room& room = roomIt.value();
        if (room.isFull())
            return ErrorType::RoomFull;
        if (room.findByNpid(m_info.npid))
            return ErrorType::RoomAlreadyJoined;
        if (room.roomPassword.has_value()) {
            const QByteArray given(req.room_password().data(),
                                   static_cast<int>(req.room_password().size()));
            const QByteArray& expected = room.roomPassword.value();
            const bool givenBlank = IsBlankRoomPassword(given);
            const bool expectedBlank = IsBlankRoomPassword(expected);
            // passwdSlotMask==0 means no slot requires the session password. MBON
            // player-match still attaches a non-zero 8-byte pointer on create, but
            // the search-join path sends no password.
            const bool publicSlotsOnly = room.passwdSlotMask == 0;
            if (given != expected && !(givenBlank && expectedBlank) &&
                !(givenBlank && publicSlotsOnly)) {
                qWarning().nospace().noquote()
                    << "JoinRoom: " << m_info.npid << " password mismatch room=" << roomId
                    << " given_len=" << given.size() << " given_blank=" << givenBlank
                    << " stored_len=" << expected.size() << " stored_blank=" << expectedBlank
                    << " passwdMask=" << Qt::hex << room.passwdSlotMask;
                return ErrorType::RoomPasswordMismatch;
            }
            if (givenBlank && publicSlotsOnly && !expectedBlank) {
                qInfo() << "JoinRoom:" << m_info.npid << "open public slots, skipping session "
                        << "password room=" << roomId;
            }
        }
        const uint64_t accountId = static_cast<uint64_t>(m_info.userId);
        if ((!room.allowedUsers.isEmpty() && !room.allowedUsers.contains(m_info.npid)) ||
            (!room.allowedAccountIds.isEmpty() && !room.allowedAccountIds.contains(accountId)) ||
            room.blockedUsers.contains(m_info.npid) || room.blockedAccountIds.contains(accountId)) {
            return ErrorType::Blocked;
        }

        RoomMember joiner;
        joiner.userId = m_info.userId;
        joiner.npid = m_info.npid;
        joiner.avatarUrl = m_info.avatarUrl;
        GetSelfSignalingAddr(joiner.addr, joiner.port);
        joiner.natType = SelfNatType();
        for (const auto& id : req.blocked_online_ids())
            joiner.blockedUsers.append(QString::fromStdString(id));
        for (const auto id : req.blocked_account_ids())
            joiner.blockedAccountIds.append(static_cast<uint64_t>(id));
        for (const auto& member : room.members) {
            const uint64_t memberAccountId = static_cast<uint64_t>(member.userId);
            if (joiner.blockedUsers.contains(member.npid) ||
                joiner.blockedAccountIds.contains(memberAccountId) ||
                member.blockedUsers.contains(m_info.npid) ||
                member.blockedAccountIds.contains(accountId)) {
                return ErrorType::Blocked;
            }
        }
        joiner.joinDate = MatchingTimestampUsec();
        joiner.teamId = static_cast<uint8_t>(req.team_id());
        if (req.member_bin_attrs_size() > 0) {
            const auto& a = req.member_bin_attrs(0);
            joiner.memberBinAttr.set = true;
            joiner.memberBinAttr.attrId = static_cast<uint16_t>(a.attr_id());
            joiner.memberBinAttr.data =
                QByteArray(a.data().data(), static_cast<int>(a.data().size()));
            joiner.memberBinAttr.updateDate = joiner.joinDate;
        }

        RoomMember* member = room.addMember(joiner);
        myMemberId = member->memberId;
        maxSlot = room.maxSlot;

        const uint16_t curMemberNum = static_cast<uint16_t>(room.members.size());
        RecomputeRoomSlotCounts(room);
        if (curMemberNum >= room.maxSlot)
            room.flagAttr |= Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;

        m_matching.roomId = roomId;
        m_matching.myMemberId = myMemberId;
        m_matching.isRoomOwner = false;
        m_matching.maxSlots = maxSlot;
        m_matching.roomFlags = room.flagAttr;
        m_matching.serverId = room.serverId;
        m_matching.worldId = room.worldId;
        m_matching.lobbyId = room.lobbyId;

        shadnet::JoinRoomReply rep;
        rep.set_room_id(roomId);
        rep.set_member_id(myMemberId);
        rep.set_max_slots(maxSlot);
        rep.set_flags(room.flagAttr);
        rep.set_cur_members(curMemberNum);
        *rep.mutable_details() = BuildCreateJoinResponse(room, *member);
        appendProto(reply, rep);
    }

    qInfo() << "Room" << roomId << m_info.npid << "joined mid=" << myMemberId;

    // MemberJoined to existing members (0x1101)
    {
        RoomMember joinedCopy;
        {
            QReadLocker lk(&m_shared->matching.roomsLock);
            auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
            if (roomIt != m_shared->matching.rooms.end()) {
                if (const RoomMember* m = roomIt->findById(myMemberId))
                    joinedCopy = *m;
            }
        }
        SendRoomMemberEvent(roomId, Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_JOINED,
                            Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_SERVER_OPERATION, joinedCopy,
                            m_info.npid);
        qDebug() << "  -> MemberJoined room=" << roomId << "mid=" << myMemberId
                 << "to existing members";
    }

    return ErrorType::NoError;
}

ErrorType ClientSession::CmdLeaveRoom(StreamExtractor& data, QByteArray& reply) {
    shadnet::LeaveRoomRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint64_t roomId = req.room_id();

    uint16_t myMemberId = 0;
    bool wasOwner = false;
    bool roomDestroyed = false;

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;
        Room& room = roomIt.value();

        const RoomMember* me = room.findByNpid(m_info.npid);
        if (!me)
            return ErrorType::RoomMissing;
        myMemberId = me->memberId;
        wasOwner = (myMemberId == room.ownerMemberId);

        const uint32_t worldId = room.worldId;
        const uint64_t lobbyId = room.lobbyId;

        room.removeMember(myMemberId);
        room.ownerSuccession.removeAll(myMemberId);

        if (room.isEmpty()) {
            m_shared->matching.rooms.erase(roomIt);
            if (worldId != 0)
                m_shared->matching.worldRooms[{m_matching.matchingKey, worldId}].removeAll(roomId);
            else if (lobbyId != 0)
                m_shared->matching.lobbyRooms[{m_matching.matchingKey, lobbyId}].removeAll(roomId);
            roomDestroyed = true;
            qInfo() << "Room" << roomId << "destroyed";
        } else {
            RecomputeRoomSlotCounts(room);
            room.flagAttr &= ~Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;

            if (wasOwner) {
                uint16_t newOwner = 0;
                while (!room.ownerSuccession.isEmpty()) {
                    const uint16_t cand = room.ownerSuccession.takeFirst();
                    if (room.members.contains(cand)) {
                        newOwner = cand;
                        break;
                    }
                }
                if (newOwner == 0)
                    newOwner = room.members.begin()->memberId;
                room.ownerMemberId = newOwner;
                if (RoomMember* om = room.findById(newOwner))
                    om->flagAttr |= Matching2::ORBIS_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER;
                qInfo() << "Room" << roomId << "owner -> mid" << newOwner;
            }
        }
    }

    ResetMatchingRoomState(roomId);
    qInfo() << "Room" << roomId << m_info.npid << "left mid=" << myMemberId;

    // Notify remaining members (MemberLeft, 0x1102)
    if (!roomDestroyed) {
        RoomMember left;
        left.memberId = myMemberId;
        left.npid = m_info.npid;
        SendRoomMemberEvent(roomId, Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_LEFT,
                            Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_LEAVE_ACTION, left);
        qDebug() << "  -> MemberLeft room=" << roomId << "npid=" << m_info.npid
                 << "mid=" << myMemberId << "to remaining members";
    }

    shadnet::LeaveRoomReply rep;
    rep.set_room_id(roomId);
    appendProto(reply, rep);
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdKickoutRoomMember(StreamExtractor& data, QByteArray& reply) {
    shadnet::KickoutRoomMemberRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint64_t roomId = req.room_id();
    uint16_t targetMemberId = static_cast<uint16_t>(req.target_member_id());
    uint32_t blockKickFlag = req.block_kick_flag();

    QString targetNpid;

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;
        Room& room = roomIt.value();
        const RoomMember* initiator = room.findByNpid(m_info.npid);
        if (!initiator)
            return ErrorType::RoomMissing;
        if (room.ownerMemberId != initiator->memberId)
            return ErrorType::Unauthorized;
        if (targetMemberId == 0 || targetMemberId == initiator->memberId)
            return ErrorType::InvalidInput;
        auto targetIt = room.members.find(targetMemberId);
        if (targetIt == room.members.end())
            return ErrorType::NotFound;

        targetNpid = targetIt->npid;

        if (blockKickFlag && !room.blockedUsers.contains(targetNpid))
            room.blockedUsers.append(targetNpid);

        room.removeMember(targetMemberId);
        room.ownerSuccession.removeAll(targetMemberId);
        RecomputeRoomSlotCounts(room);
        room.flagAttr &= ~Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;
    }

    qInfo() << "Room" << roomId << m_info.npid << "kicked" << targetNpid << "mid=" << targetMemberId
            << "blockKickFlag=" << blockKickFlag;

    // KickedOut to the removed member (0x1103)
    SendRoomEventToTarget(roomId, Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_KICKEDOUT,
                          Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_KICKOUT_ACTION,
                          MATCHING2_KICKEDOUT_STATUS_CODE, targetNpid);
    qDebug() << "  -> KickedOut room=" << roomId << "to" << targetNpid;

    // MemberLeft to remaining members (0x1102, KICKOUT cause)
    {
        RoomMember left;
        left.memberId = targetMemberId;
        left.npid = targetNpid;
        SendRoomMemberEvent(roomId, Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_LEFT,
                            Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_KICKOUT_ACTION, left,
                            targetNpid);
        qDebug() << "  -> MemberLeft (kicked) room=" << roomId << "mid=" << targetMemberId;
    }

    shadnet::KickoutRoomMemberReply rep;
    rep.set_room_id(roomId);
    appendProto(reply, rep);
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdGetWorldInfoList(StreamExtractor& data, QByteArray& reply) {
    shadnet::GetWorldInfoListRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    const uint16_t serverId = static_cast<uint16_t>(req.server_id());

    shadnet::GetWorldInfoListReply rep;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);

        auto countRoomsAndMembers = [&](uint32_t worldId, uint32_t& roomsNum,
                                        uint32_t& roomMembersNum) {
            roomsNum = 0;
            roomMembersNum = 0;
            const QVector<uint64_t> ids =
                m_shared->matching.worldRooms.value({m_matching.matchingKey, worldId});
            for (uint64_t rid : ids) {
                auto it = m_shared->matching.rooms.find({m_matching.matchingKey, rid});
                if (it == m_shared->matching.rooms.end())
                    continue;
                ++roomsNum;
                roomMembersNum += static_cast<uint32_t>(it.value().members.size());
            }
        };

        const QVector<WorldConfig> configs =
            m_shared->matching.worldConfigs.value(m_matching.matchingKey);

        if (!configs.isEmpty()) {
            for (const WorldConfig& wc : configs) {
                if (serverId != 0 && wc.serverId != serverId)
                    continue;
                uint32_t roomsNum = 0;
                uint32_t roomMembersNum = 0;
                countRoomsAndMembers(wc.worldId, roomsNum, roomMembersNum);

                shadnet::MatchingWorld* w = rep.add_worlds();
                w->set_world_id(wc.worldId);
                w->set_lobbies_num(wc.lobbiesNum);
                w->set_max_lobby_members(wc.maxLobbyMembersNum);
                w->set_lobby_members_num(0);
                w->set_rooms_num(roomsNum);
                w->set_room_members_num(roomMembersNum);
            }
        } else {
            qWarning() << "GetWorldInfoList: no worlds.cfg entry for" << m_matching.matchingKey
                       << "- falling back to a single default world; titles that index a fixed "
                          "world array will reject this list";
            QVector<uint32_t> worldIds;
            for (auto it = m_shared->matching.worldRooms.constBegin();
                 it != m_shared->matching.worldRooms.constEnd(); ++it) {
                if (it.key().first != m_matching.matchingKey)
                    continue;
                const uint32_t worldId = it.key().second;
                if (!worldIds.contains(worldId))
                    worldIds.append(worldId);
            }
            if (worldIds.isEmpty())
                worldIds.append(1);

            for (uint32_t worldId : worldIds) {
                uint32_t roomsNum = 0;
                uint32_t roomMembersNum = 0;
                countRoomsAndMembers(worldId, roomsNum, roomMembersNum);

                shadnet::MatchingWorld* w = rep.add_worlds();
                w->set_world_id(worldId);
                w->set_lobbies_num(0);
                w->set_max_lobby_members(0);
                w->set_lobby_members_num(0);
                w->set_rooms_num(roomsNum);
                w->set_room_members_num(roomMembersNum);
            }
        }
    }

    appendProto(reply, rep);
    qInfo() << "GetWorldInfoList:" << m_info.npid << "server=" << serverId
            << "worlds=" << rep.worlds_size();
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdGetLobbyInfoList(StreamExtractor& data, QByteArray& reply) {
    shadnet::GetLobbyInfoListRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    const uint32_t worldId = req.world_id();
    if (worldId == 0)
        return ErrorType::Invalid;

    uint32_t rangeStart = req.range_filter_start();
    if (rangeStart < 1)
        rangeStart = 1;
    uint32_t rangeMax = req.range_filter_max();
    if (rangeMax == 0 || rangeMax > RANGE_FILTER_MAX)
        rangeMax = RANGE_FILTER_MAX;

    uint32_t lobbiesNum = 0;
    uint16_t serverId = 1;
    uint32_t maxLobbyMembers = 0;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        const QVector<WorldConfig> configs =
            m_shared->matching.worldConfigs.value(m_matching.matchingKey);
        for (const WorldConfig& wc : configs) {
            if (wc.worldId != worldId)
                continue;
            lobbiesNum = wc.lobbiesNum;
            serverId = wc.serverId;
            maxLobbyMembers = wc.maxLobbyMembersNum;
            break;
        }
    }

    shadnet::GetLobbyInfoListReply rep;
    rep.set_range_start(rangeStart);
    rep.set_range_total(lobbiesNum);

    for (uint32_t index = rangeStart; index < rangeStart + rangeMax && index <= lobbiesNum;
         ++index) {
        shadnet::MatchingLobby* l = rep.add_lobbies();
        l->set_server_id(serverId);
        l->set_world_id(worldId);
        l->set_lobby_id(MakeLobbyId(worldId, index));
        l->set_max_slot(maxLobbyMembers);
        l->set_cur_member_num(0);
        l->set_flag_attr(0);
    }

    appendProto(reply, rep);
    qInfo() << "GetLobbyInfoList:" << m_info.npid << "world=" << worldId << "start=" << rangeStart
            << "of" << lobbiesNum << "returned=" << rep.lobbies_size();
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdSearchRoom(StreamExtractor& data, QByteArray& reply) {
    shadnet::SearchRoomRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    const uint32_t worldId = req.world_id();
    const uint64_t lobbyId = req.lobby_id();

    uint32_t rangeStart = req.range_filter_start();
    if (rangeStart < 1)
        rangeStart = 1;
    uint32_t rangeMax = req.range_filter_max();
    if (rangeMax == 0 || rangeMax > RANGE_FILTER_MAX)
        rangeMax = RANGE_FILTER_MAX;
    const QVector<uint16_t> requestedAttrIds = RequestedAttrIds(req);

    shadnet::SearchRoomReply rep;
    uint32_t total = 0;
    int candidateCount = 0;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);

        QVector<uint64_t> candidates;
        if (worldId != 0)
            candidates = m_shared->matching.worldRooms.value({m_matching.matchingKey, worldId});
        else if (lobbyId != 0)
            candidates = m_shared->matching.lobbyRooms.value({m_matching.matchingKey, lobbyId});
        candidateCount = candidates.size();

        QVector<const Room*> matches;
        for (uint64_t rid : candidates) {
            auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, rid});
            if (roomIt == m_shared->matching.rooms.end()) {
                qWarning() << "  search skip STALE candidate rid=" << rid
                           << "key=" << m_matching.matchingKey
                           << "(present in world index but missing from rooms map)";
                continue;
            }
            if (!RoomMatchesFilters(roomIt.value(), req))
                continue;
            matches.append(&roomIt.value());
        }

        total = static_cast<uint32_t>(matches.size());
        uint32_t emitted = 0;
        for (uint32_t i = rangeStart - 1;
             i < static_cast<uint32_t>(matches.size()) && emitted < rangeMax; ++i, ++emitted) {
            *rep.add_rooms() = BuildRoomDataExternal(*matches[i], requestedAttrIds);
        }
    }

    rep.set_range_start(rangeStart);
    rep.set_range_total(total);
    rep.set_range_result(static_cast<uint32_t>(rep.rooms_size()));
    appendProto(reply, rep);

    qInfo() << "SearchRoom:" << m_info.npid << "world=" << worldId << "lobby=" << lobbyId
            << "key=" << m_matching.matchingKey << "attrIds=" << requestedAttrIds.size()
            << "candidates=" << candidateCount << "total=" << total
            << "returned=" << rep.rooms_size();
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdGetRoomDataExternalList(StreamExtractor& data, QByteArray& reply) {
    shadnet::GetRoomDataExternalListRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;
    const QVector<uint16_t> requestedAttrIds = RequestedAttrIds(req);

    shadnet::GetRoomDataExternalListReply rep;
    int found = 0;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        for (int i = 0; i < req.room_ids_size(); ++i) {
            const uint64_t rid = req.room_ids(i);
            auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, rid});
            if (roomIt == m_shared->matching.rooms.end())
                continue;
            *rep.add_rooms() = BuildRoomDataExternal(roomIt.value(), requestedAttrIds);
            ++found;
        }
    }
    appendProto(reply, rep);

    qInfo() << "GetRoomDataExternalList:" << m_info.npid << "key=" << m_matching.matchingKey
            << "requested=" << req.room_ids_size() << "attrIds=" << requestedAttrIds.size()
            << "found=" << found;
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdGetRoomMemberDataExternalList(StreamExtractor& data,
                                                          QByteArray& reply) {
    shadnet::GetRoomMemberDataExternalListRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    shadnet::GetRoomMemberDataExternalListReply rep;
    bool found = false;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, req.room_id()});
        if (roomIt != m_shared->matching.rooms.end()) {
            found = true;
            const Room& room = roomIt.value();
            QList<uint16_t> memberIds = room.members.keys();
            std::sort(memberIds.begin(), memberIds.end());
            for (uint16_t memberId : memberIds) {
                auto memberIt = room.members.constFind(memberId);
                if (memberIt == room.members.constEnd())
                    continue;
                const RoomMember& member = memberIt.value();
                auto* dst = rep.add_members();
                dst->set_npid(member.npid.toStdString());
                dst->set_member_id(member.memberId);
                dst->set_account_id(static_cast<uint64_t>(member.userId));
                dst->set_platform(member.platform);
                dst->set_join_date(member.joinDate);
                dst->set_role(member.memberId == room.ownerMemberId ? 2 : 1);
            }
        }
    }
    if (!found)
        return ErrorType::NotFound;

    appendProto(reply, rep);
    qInfo() << "GetRoomMemberDataExternalList:" << m_info.npid
            << "room=" << static_cast<qulonglong>(req.room_id())
            << "members=" << rep.members_size();
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdGetUserInfoList(StreamExtractor& data, QByteArray& reply) {
    shadnet::GetUserInfoListRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    shadnet::GetUserInfoListReply rep;
    int found = 0;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, m_matching.roomId});
        for (int i = 0; i < req.npids_size(); ++i) {
            const QString npid = QString::fromStdString(req.npids(i));
            auto* user = rep.add_users();
            user->set_npid(req.npids(i));
            if (roomIt != m_shared->matching.rooms.end()) {
                const RoomMember* member = roomIt.value().findByNpid(npid);
                if (member) {
                    user->set_account_id(static_cast<uint64_t>(member->userId));
                    user->set_platform(member->platform);
                    ++found;
                }
            }
            const auto infoIt =
                m_shared->matching.userInfo.constFind({m_matching.matchingKey, npid});
            if (infoIt != m_shared->matching.userInfo.constEnd()) {
                if (user->account_id() == 0 && npid == m_info.npid) {
                    user->set_account_id(static_cast<uint64_t>(m_info.userId));
                    user->set_platform(3);
                }
                for (const BinAttrSlot& slot : infoIt.value()) {
                    if (!slot.set)
                        continue;
                    bool wanted = req.attr_ids_size() == 0;
                    for (int j = 0; !wanted && j < req.attr_ids_size(); ++j)
                        wanted = static_cast<uint16_t>(req.attr_ids(j)) == slot.attrId;
                    if (!wanted)
                        continue;
                    auto* attr = user->add_user_bin_attrs();
                    attr->set_attr_id(slot.attrId);
                    attr->set_data(slot.data.constData(), slot.data.size());
                }
                if (user->user_bin_attrs_size() > 0 && user->account_id() == 0)
                    ++found;
            }
        }
    }
    appendProto(reply, rep);

    qInfo() << "GetUserInfoList:" << m_info.npid << "requested=" << req.npids_size()
            << "found=" << found;
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdSetUserInfo(StreamExtractor& data, QByteArray& reply) {
    shadnet::SetUserInfoRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    QVector<BinAttrSlot> attrs;
    attrs.reserve(req.user_bin_attrs_size());
    for (int i = 0; i < req.user_bin_attrs_size(); ++i) {
        const auto& src = req.user_bin_attrs(i);
        BinAttrSlot slot;
        slot.set = true;
        slot.attrId = static_cast<uint16_t>(src.attr_id());
        slot.data = QByteArray(src.data().data(), static_cast<int>(src.data().size()));
        attrs.append(std::move(slot));
    }

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        m_shared->matching.userInfo.insert({m_matching.matchingKey, m_info.npid}, std::move(attrs));
    }

    shadnet::SetUserInfoReply rep;
    appendProto(reply, rep);

    qInfo() << "SetUserInfo:" << m_info.npid << "server=" << req.server_id()
            << "binAttrs=" << req.user_bin_attrs_size();
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdRequestSignalingInfos(StreamExtractor& data, QByteArray& reply) {
    shadnet::RequestSignalingInfosRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    QString targetNpid = QString::fromStdString(req.target_npid());

    QString targetIp;
    uint16_t targetPort = 0;
    uint8_t targetNatType = 0;
    {
        QReadLocker lk(&m_shared->matching.udpLock);
        auto it = m_shared->matching.udpExt.find(targetNpid);
        if (it != m_shared->matching.udpExt.end() &&
            it.value().IsFresh(QDateTime::currentMSecsSinceEpoch(), UDP_ENDPOINT_TTL_MS)) {
            targetIp = it.value().addr;
            targetPort = it.value().port;
            targetNatType = it.value().natType;
        }
    }
    if (targetPort == 0) {
        QReadLocker lk(&m_shared->matching.roomsLock);
        for (auto it = m_shared->matching.rooms.constBegin();
             it != m_shared->matching.rooms.constEnd(); ++it) {
            if (it.key().first != m_matching.matchingKey)
                continue;
            const RoomMember* tm = it.value().findByNpid(targetNpid);
            if (tm && tm->port != 0) {
                targetIp = tm->addr;
                targetPort = tm->port;
                targetNatType = tm->natType;
                break;
            }
        }
    }
    // An address without a port is not an endpoint. Reporting one anyway would send the caller's
    // handshake nowhere and leave it blaming the peer instead of the missing STUN registration.
    if (targetIp.isEmpty() || targetPort == 0) {
        qWarning().nospace().noquote() << "RequestSignalingInfos: " << m_info.npid << " -> "
                                       << targetNpid << " has no registered UDP endpoint";
        return ErrorType::NotFound;
    }

    uint16_t targetMemberId = 0;
    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        for (auto it = m_shared->matching.rooms.constBegin();
             it != m_shared->matching.rooms.constEnd(); ++it) {
            if (it.key().first != m_matching.matchingKey)
                continue;
            const RoomMember* tm = it.value().findByNpid(targetNpid);
            if (tm) {
                targetMemberId = tm->memberId;
                break;
            }
        }
    }

    qInfo() << "RequestSignalingInfos:" << m_info.npid << "->" << targetNpid
            << "(mid=" << targetMemberId << ") target=" << targetIp << ":" << targetPort;

    shadnet::RequestSignalingInfosReply rep;
    rep.set_target_npid(targetNpid.toStdString());
    rep.set_target_ip(targetIp.toStdString());
    rep.set_target_port(targetPort);
    rep.set_target_member_id(targetMemberId);
    rep.set_target_nat_type(targetNatType);
    appendProto(reply, rep);

    return ErrorType::NoError;
}

ErrorType ClientSession::CmdSendRoomMessage(StreamExtractor& data, QByteArray& reply) {
    shadnet::SendRoomMessageRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    const uint64_t roomId = req.room_id();
    const uint8_t castType = static_cast<uint8_t>(req.cast_type());
    RoomMember srcMember;
    QVector<QString> targetNpids;
    QVector<uint16_t> targetMemberIds;

    {
        QReadLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;

        const Room& room = roomIt.value();
        const RoomMember* src = room.findByNpid(m_info.npid);
        if (!src)
            return ErrorType::RoomMissing;
        srcMember = *src;

        auto addTarget = [&](const RoomMember* target) {
            if (!target || target->npid == m_info.npid)
                return;
            targetNpids.append(target->npid);
            targetMemberIds.append(target->memberId);
        };
        auto addTargetById = [&](uint16_t memberId) {
            auto it = room.members.find(memberId);
            if (it != room.members.end())
                addTarget(&(*it));
        };

        if (castType == MATCHING2_CASTTYPE_UNICAST) {
            if (req.dst_member_ids_size() <= 0)
                return ErrorType::InvalidInput;
            addTargetById(static_cast<uint16_t>(req.dst_member_ids(0)));
        } else if (castType == MATCHING2_CASTTYPE_MULTICAST) {
            for (int i = 0; i < req.dst_member_ids_size(); ++i) {
                addTargetById(static_cast<uint16_t>(req.dst_member_ids(i)));
            }
        } else if (castType == MATCHING2_CASTTYPE_BROADCAST) {
            for (auto it = room.members.begin(); it != room.members.end(); ++it)
                addTarget(&(*it));
        } else {
            return ErrorType::InvalidInput;
        }
    }

    if (targetNpids.isEmpty() &&
        (castType == MATCHING2_CASTTYPE_UNICAST || castType == MATCHING2_CASTTYPE_MULTICAST)) {
        return ErrorType::NotFound;
    }

    shadnet::NotifyRoomMessage notif;
    notif.set_ctx_id(m_matching.ctxId);
    notif.set_room_id(roomId);
    notif.set_src_member_id(srcMember.memberId);
    notif.set_event(MATCHING2_ROOM_MSG_EVENT_MESSAGE);
    notif.set_cast_type(castType);
    notif.set_src_npid(srcMember.npid.toStdString());
    notif.set_src_account_id(static_cast<uint64_t>(srcMember.userId));
    notif.set_src_platform(srcMember.platform);
    notif.set_msg(req.msg());
    for (const uint16_t memberId : targetMemberIds)
        notif.add_dst_member_ids(memberId);

    QByteArray notifPayload;
    appendProto(notifPayload, notif);
    for (const QString& targetNpid : targetNpids)
        SendMatchingNotification(NotificationType::RoomMessage, notifPayload, targetNpid);

    qInfo() << "SendRoomMessage:" << m_info.npid << "room=" << roomId << "cast=" << castType
            << "targets=" << targetNpids.size() << "bytes=" << req.msg().size();

    shadnet::SendRoomMessageReply rep;
    rep.set_room_id(roomId);
    appendProto(reply, rep);
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdSetRoomDataInternal(StreamExtractor& data, QByteArray& reply) {
    shadnet::SetRoomDataInternalRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint64_t roomId = req.room_id();
    uint32_t flagFilter = req.flag_filter();
    uint32_t flagAttr = req.flag_attr();
    bool hasPasswdMask = req.has_passwd_mask();
    uint64_t passwdSlotMask = req.passwd_slot_mask();

    uint32_t newFlags = 0;
    QVector<InternalBinAttrSlot> updatedSlots;
    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;
        Room& room = roomIt.value();

        const uint32_t protectedMask = Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;
        const uint32_t effFilter = flagFilter & ~protectedMask;
        room.flagAttr = (room.flagAttr & ~effFilter) | (flagAttr & effFilter);
        newFlags = room.flagAttr;

        if (hasPasswdMask) {
            room.passwdSlotMask = passwdSlotMask;
            RecomputeRoomSlotCounts(room);
        }

        const RoomMember* setter = room.findByNpid(m_info.npid);
        const uint16_t setterId = setter ? setter->memberId : 0;
        const uint64_t now = MatchingTimestampUsec();
        for (int i = 0; i < req.bin_attrs_size(); ++i) {
            const auto& a = req.bin_attrs(i);
            const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
            int idx = -1;
            if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_1_ID)
                idx = 0;
            else if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_2_ID)
                idx = 1;
            if (idx < 0)
                continue;
            auto& slot = room.internalBinAttr[idx];
            slot.set = true;
            slot.attrId = attrId;
            slot.data = QByteArray(a.data().data(), static_cast<int>(a.data().size()));
            slot.updateDate = now;
            slot.updateMemberId = setterId;
            updatedSlots.append(slot);
        }

        qInfo() << "SetRoomDataInternal: room=" << roomId << "flags=" << Qt::hex << newFlags
                << "binAttrs=" << req.bin_attrs_size();
    }

    // Broadcast UpdatedRoomDataInternal to all other members (0x1106)
    {
        shadnet::NotifyRoomEvent pb;
        pb.set_ctx_id(m_matching.ctxId);
        pb.set_room_id(roomId);
        pb.set_event(Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_UPDATED_ROOM_DATA_INTERNAL);
        pb.set_event_cause(Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_SERVER_OPERATION);
        pb.set_flags(newFlags);
        if (hasPasswdMask) {
            pb.set_has_passwd_mask(true);
            pb.set_passwd_slot_mask(passwdSlotMask);
        }
        for (const auto& slot : updatedSlots) {
            auto* ba = pb.add_bin_attrs();
            ba->set_attr_id(slot.attrId);
            ba->set_data(slot.data.constData(), slot.data.size());
            ba->set_update_date(slot.updateDate);
            ba->set_update_member_id(slot.updateMemberId);
        }
        QByteArray notifPayload;
        appendProto(notifPayload, pb);
        NotifyRoomMembers(NotificationType::RoomEvent, notifPayload, m_matching.matchingKey, roomId,
                          m_info.npid);
        qDebug() << "  -> UpdatedRoomDataInternal room=" << roomId << "broadcast (excl. sender)"
                 << "attrs=" << updatedSlots.size();
    }

    shadnet::SetRoomDataInternalReply rep;
    rep.set_room_id(roomId);
    appendProto(reply, rep);
    return ErrorType::NoError;
}

ErrorType ClientSession::CmdSetRoomDataExternal(StreamExtractor& data, QByteArray& reply) {
    shadnet::SetRoomDataExternalRequest req;
    if (!decodeProto(req, data) || data.error())
        return ErrorType::Malformed;

    uint64_t roomId = req.room_id();

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return ErrorType::RoomMissing;
        Room& room = roomIt.value();

        for (int i = 0; i < req.search_int_attrs_size(); ++i) {
            const auto& a = req.search_int_attrs(i);
            const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
            if (attrId < Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID ||
                attrId > Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_8_ID)
                continue;
            const int idx =
                attrId - Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_INT_ATTR_EXTERNAL_1_ID;
            room.searchIntAttr[idx].set = true;
            room.searchIntAttr[idx].attrId = attrId;
            room.searchIntAttr[idx].value = a.attr_value();
        }
        for (int i = 0; i < req.search_bin_attrs_size(); ++i) {
            const auto& a = req.search_bin_attrs(i);
            const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
            if (attrId != Matching2::ORBIS_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID)
                continue;
            room.searchBinAttr.set = true;
            room.searchBinAttr.attrId = attrId;
            room.searchBinAttr.data =
                QByteArray(a.data().data(), static_cast<int>(a.data().size()));
        }
        for (int i = 0; i < req.ext_bin_attrs_size(); ++i) {
            const auto& a = req.ext_bin_attrs(i);
            const uint16_t attrId = static_cast<uint16_t>(a.attr_id());
            int idx = -1;
            if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID)
                idx = 0;
            else if (attrId == Matching2::ORBIS_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID)
                idx = 1;
            if (idx < 0)
                continue;
            room.externalBinAttr[idx].set = true;
            room.externalBinAttr[idx].attrId = attrId;
            room.externalBinAttr[idx].data =
                QByteArray(a.data().data(), static_cast<int>(a.data().size()));
        }

        qInfo() << "SetRoomDataExternal: room=" << roomId
                << "searchIntAttrs=" << req.search_int_attrs_size()
                << "searchBinAttrs=" << req.search_bin_attrs_size()
                << "extBinAttrs=" << req.ext_bin_attrs_size();
    }

    shadnet::SetRoomDataExternalReply rep;
    rep.set_room_id(roomId);
    appendProto(reply, rep);
    return ErrorType::NoError;
}

// ── DoLeaveRoom (reusable for both CmdLeaveRoom and disconnect cleanup) ────────

void ClientSession::DoLeaveRoom(uint64_t roomId) {
    uint16_t myMemberId = 0;
    bool roomDestroyed = false;

    {
        QWriteLocker lk(&m_shared->matching.roomsLock);
        auto roomIt = m_shared->matching.rooms.find({m_matching.matchingKey, roomId});
        if (roomIt == m_shared->matching.rooms.end())
            return;
        Room& room = roomIt.value();

        const RoomMember* me = room.findByNpid(m_info.npid);
        if (!me)
            return;
        myMemberId = me->memberId;
        const bool wasOwner = (myMemberId == room.ownerMemberId);

        const uint32_t worldId = room.worldId;
        const uint64_t lobbyId = room.lobbyId;

        room.removeMember(myMemberId);
        room.ownerSuccession.removeAll(myMemberId);

        if (room.isEmpty()) {
            m_shared->matching.rooms.erase(roomIt);
            if (worldId != 0)
                m_shared->matching.worldRooms[{m_matching.matchingKey, worldId}].removeAll(roomId);
            else if (lobbyId != 0)
                m_shared->matching.lobbyRooms[{m_matching.matchingKey, lobbyId}].removeAll(roomId);
            roomDestroyed = true;
            qInfo() << "Room" << roomId << "destroyed (disconnect)";
        } else {
            RecomputeRoomSlotCounts(room);
            room.flagAttr &= ~Matching2::ORBIS_NP_MATCHING2_ROOM_FLAG_ATTR_FULL;
            if (wasOwner) {
                uint16_t newOwner = 0;
                while (!room.ownerSuccession.isEmpty()) {
                    const uint16_t cand = room.ownerSuccession.takeFirst();
                    if (room.members.contains(cand)) {
                        newOwner = cand;
                        break;
                    }
                }
                if (newOwner == 0)
                    newOwner = room.members.begin()->memberId;
                room.ownerMemberId = newOwner;
                if (RoomMember* om = room.findById(newOwner))
                    om->flagAttr |= Matching2::ORBIS_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER;
                qInfo() << "Room" << roomId << "owner -> mid" << newOwner << "(disconnect)";
            }
        }
    }

    ResetMatchingRoomState(roomId);

    if (!roomDestroyed) {
        RoomMember left;
        left.memberId = myMemberId;
        left.npid = m_info.npid;
        SendRoomMemberEvent(roomId, Matching2::ORBIS_NP_MATCHING2_ROOM_EVENT_MEMBER_LEFT,
                            Matching2::ORBIS_NP_MATCHING2_EVENT_CAUSE_LEAVE_ACTION, left);
        qDebug() << "  -> MemberLeft room=" << roomId << "npid=" << m_info.npid
                 << "mid=" << myMemberId << "to remaining members (disconnect)";
    }
}

// ── Disconnect cleanup ────────────────────────────────────────────────────────

void ClientSession::CleanupMatchingOnDisconnect() {
    if (!m_matching.initialized)
        return;

    if (m_matching.roomId != 0)
        DoLeaveRoom(m_matching.roomId);

    qInfo() << "Matching cleanup for" << m_info.npid;
}
