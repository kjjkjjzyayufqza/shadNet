// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#include "webapi_routes_identity.h"

#include <optional>
#include <utility>

#include <QDateTime>
#include <QDebug>
#include <QHttpServer>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QTimeZone>
#include <QUrl>
#include <QUrlQuery>

#include "database.h"
#include "webapi_auth.h"
#include "webapi_routes_common.h"

namespace WebApiRoutes {

constexpr quint32 WEBAPI_RESOURCE_NOT_FOUND = 2113549; // target resource does not exist

bool IsValidOnlineId(const QString& onlineId) {
    static const QRegularExpression re(
        QRegularExpression::anchoredPattern(QStringLiteral("[a-zA-Z][a-zA-Z0-9_-]{2,15}")));
    return re.match(onlineId).hasMatch();
}

std::optional<QDateTime> ParseAsOf(const QString& raw) {
    QString value = raw.trimmed();
    if (value.isEmpty()) {
        return std::nullopt;
    }
    static const QRegularExpression compactOffset(QStringLiteral("([+-])(\\d{2})(\\d{2})\\z"));
    const auto m = compactOffset.match(value);
    if (m.hasMatch()) {
        value.replace(m.capturedStart(), m.capturedLength(),
                      m.captured(1) + m.captured(2) + QLatin1Char(':') + m.captured(3));
    }
    QDateTime dt = QDateTime::fromString(value, Qt::ISODateWithMs);
    if (!dt.isValid()) {
        dt = QDateTime::fromString(value, Qt::ISODate);
    }
    if (!dt.isValid()) {
        return std::nullopt;
    }
    if (dt.timeSpec() == Qt::LocalTime) {
        dt.setTimeZone(QTimeZone(QTimeZone::UTC));
    }
    return dt.toUTC();
}

void RegisterIdentityRoutes(QHttpServer& http, Database& db) {
    // GET /v2/accounts/map/onlineId2accountId/<online_id>[?asOf=<RFC 3339 timestamp>]
    http.route(
        "/v2/accounts/map/onlineId2accountId/<arg>",
        [&db](const QString& onlineId, const QHttpServerRequest& req) -> QHttpServerResponse {
            static const QSet<QString> kKnown = {QStringLiteral("asOf")};
            LogUnsupportedQueryParams(req, kKnown);

            auto auth = WebApiAuth::Authenticate(req, db);
            if (!auth.userId.has_value()) {
                return std::move(auth.errorResponse);
            }

            if (!IsValidOnlineId(onlineId)) {
                return JsonError(
                    QHttpServerResponse::StatusCode::BadRequest, UP_INVALID_QUERY_PARAM,
                    QStringLiteral("Invalid parameter in request path (parameter: 'online_id')"));
            }

            const QUrlQuery query(req.url());
            const bool hasAsOf = query.hasQueryItem(QStringLiteral("asOf"));
            QDateTime asOf;
            if (hasAsOf) {
                const auto parsed =
                    ParseAsOf(query.queryItemValue(QStringLiteral("asOf"), QUrl::FullyDecoded));
                if (!parsed.has_value()) {
                    return JsonError(
                        QHttpServerResponse::StatusCode::BadRequest, UP_INVALID_QUERY_PARAM,
                        QStringLiteral("Invalid parameter in query string (parameter: 'asOf')"));
                }
                asOf = *parsed;
            }

            const auto userId = db.GetUserId(onlineId);
            if (!userId.has_value()) {
                return JsonError(QHttpServerResponse::StatusCode::NotFound,
                                 WEBAPI_RESOURCE_NOT_FOUND,
                                 QStringLiteral("The online ID has never been associated with an "
                                                "account (online_id: '%1')")
                                     .arg(onlineId));
            }
            const QString canonicalId = db.GetUsername(*userId).value_or(onlineId);
            if (hasAsOf) {
                const auto created = db.GetAccountCreationTime(*userId);
                if (created.has_value() && asOf.toSecsSinceEpoch() < *created) {
                    return JsonError(
                        QHttpServerResponse::StatusCode::NotFound, WEBAPI_RESOURCE_NOT_FOUND,
                        QStringLiteral("The online ID was not associated with an account at the "
                                       "requested time (online_id: '%1')")
                            .arg(onlineId));
                }
            }

            QJsonObject body;
            body.insert(QStringLiteral("accountId"), QString::number(*userId));
            body.insert(QStringLiteral("isCurrent"), true);
            if (!hasAsOf) {
                body.insert(QStringLiteral("isRecycled"), false);
            }
            body.insert(QStringLiteral("npId"), EncodeNpId(canonicalId));
            body.insert(QStringLiteral("onlineId"), canonicalId);

            if (hasAsOf) {
                qInfo() << "WebAPI: onlineId2accountId" << canonicalId << "asOf"
                        << asOf.toString(Qt::ISODateWithMs) << "->" << *userId;
            } else {
                qInfo() << "WebAPI: onlineId2accountId" << canonicalId << "->" << *userId;
            }
            return JsonOk(body);
        });

    // POST /v2/accounts/map/accountId2onlineId
    //
    // The batch reverse of the route above. MAXIBOOST ON calls it whenever it has to turn a list
    // of account ids into names - leaderboard rows, room member lists, replay authors - and until
    // now it fell through to the 404 handler, so every one of those lists came back nameless.
    //
    // Request body is a JSON array of account ids as strings. The response mirrors the singular
    // route's object, one per requested id and in the requested order, so a caller can pair them
    // up by index. An id with no account still gets an entry with an empty online id rather than
    // being dropped, which is what keeps the index pairing valid.
    http.route("/v2/accounts/map/accountId2onlineId", QHttpServerRequest::Method::Post,
               [&db](const QHttpServerRequest& req) -> QHttpServerResponse {
                   auto auth = WebApiAuth::Authenticate(req, db);
                   if (!auth.userId.has_value()) {
                       return std::move(auth.errorResponse);
                   }

                   QJsonParseError parseError{};
                   const QJsonDocument doc = QJsonDocument::fromJson(req.body(), &parseError);
                   if (parseError.error != QJsonParseError::NoError || !doc.isArray()) {
                       return JsonError(
                           QHttpServerResponse::StatusCode::BadRequest, UP_INVALID_QUERY_PARAM,
                           QStringLiteral("Request body must be a JSON array of account ids"));
                   }
                   const QJsonArray requested = doc.array();
                   if (requested.isEmpty() || requested.size() > 100) {
                       return JsonError(QHttpServerResponse::StatusCode::BadRequest,
                                        UP_INVALID_QUERY_PARAM,
                                        QStringLiteral("Account id list must hold 1..100 entries"));
                   }

                   QJsonArray mapped;
                   int resolved = 0;
                   for (const QJsonValue& value : requested) {
                       // PSN carries account ids as decimal strings because they do not survive a
                       // JSON double; accept a number as well so a caller that sent one is not
                       // silently dropped.
                       const QString idStr = value.isString()
                                                 ? value.toString()
                                                 : QString::number(value.toVariant().toLongLong());
                       bool ok = false;
                       const qint64 accountId = idStr.toLongLong(&ok);

                       QJsonObject entry;
                       entry.insert(QStringLiteral("accountId"), idStr);
                       const auto onlineId = ok ? db.GetUsername(accountId) : std::nullopt;
                       if (onlineId.has_value()) {
                           entry.insert(QStringLiteral("isCurrent"), true);
                           entry.insert(QStringLiteral("isRecycled"), false);
                           entry.insert(QStringLiteral("npId"), EncodeNpId(*onlineId));
                           entry.insert(QStringLiteral("onlineId"), *onlineId);
                           ++resolved;
                       } else {
                           entry.insert(QStringLiteral("isCurrent"), false);
                           entry.insert(QStringLiteral("isRecycled"), false);
                           entry.insert(QStringLiteral("npId"), QString());
                           entry.insert(QStringLiteral("onlineId"), QString());
                       }
                       mapped.append(entry);
                   }

                   qInfo() << "WebAPI: accountId2onlineId requested=" << requested.size()
                           << "resolved=" << resolved;
                   return QHttpServerResponse{"application/json",
                                              QJsonDocument(mapped).toJson(QJsonDocument::Compact),
                                              QHttpServerResponse::StatusCode::Ok};
               });

    // GET /v1/npServiceLabels/<label>/events2
    //
    // The tournaments feed. This server runs no PSN tournaments, but a 404 is not the same answer
    // as "none": MAXIBOOST ON stores an empty string on failure and then has nothing to
    // distinguish "no events" from "could not ask". An empty, well-formed list is the honest
    // answer and the one the title can act on.
    http.route("/v1/npServiceLabels/<arg>/events2", QHttpServerRequest::Method::Get,
               [](quint32 serviceLabel, const QHttpServerRequest& req) -> QHttpServerResponse {
                   const QUrlQuery query(req.url());
                   QJsonObject body;
                   body.insert(QStringLiteral("events"), QJsonArray{});
                   body.insert(QStringLiteral("totalResults"), 0);
                   body.insert(QStringLiteral("offset"), 0);
                   body.insert(QStringLiteral("size"), 0);
                   qInfo() << "WebAPI: events2 label=" << serviceLabel
                           << "eventType=" << query.queryItemValue(QStringLiteral("eventType"))
                           << "-> empty list";
                   return JsonOk(body);
               });
}

} // namespace WebApiRoutes
