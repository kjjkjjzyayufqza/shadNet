// SPDX-FileCopyrightText: Copyright 2026 shadNet Project
// SPDX-License-Identifier: GPL-2.0-or-later
#include "webapi_server.h"

#include <QDateTime>
#include <QDebug>
#include <QHash>
#include <QHostAddress>
#include <QHttpServerRequest>
#include <QHttpServerResponder>
#include <QHttpServerResponse>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QMutexLocker>
#include <webapi_routes_users.h>
#include "webapi_auth.h"
#include "webapi_routes_identity.h"
#include "webapi_routes_presence.h"
#include "webapi_routes_profile.h"
#include "webapi_routes_session.h"

WebApiServer::WebApiServer(QObject* parent) : QObject(parent) {}
WebApiServer::~WebApiServer() = default;

bool WebApiServer::Start(ConfigManager* config, const QString& dbPath, SharedState* shared) {
    m_config = config;
    m_shared = shared;

    m_db = std::make_unique<Database>(QStringLiteral("webapi_main"));
    if (!m_db->Open(dbPath)) {
        qCritical() << "WebApiServer: failed to open database at" << dbPath;
        return false;
    }

    m_http = std::make_unique<QHttpServer>(this);
    RegisterRoutes();

    m_tcp = std::make_unique<QTcpServer>(this);

    const QString host = m_config->GetHost();
    const quint16 port = m_config->GetWebApiPort().toUShort();
    if (!m_tcp->listen(QHostAddress(host), port)) {
        qCritical() << "WebApiServer: failed to bind" << host << ":" << port << "—"
                    << m_tcp->errorString();
        return false;
    }

    if (!m_http->bind(m_tcp.get())) {
        qCritical() << "WebApiServer: QHttpServer failed to attach to listener";
        return false;
    }

    qInfo().nospace().noquote() << "WebApiServer listening on: " << host << ":" << port;
    return true;
}

void WebApiServer::RegisterRoutes() {
    m_http->route("/status", [](const QHttpServerRequest&) {
        QJsonObject body;
        body.insert("ok", true);
        body.insert("service", "shadnet-webapi");
        return QHttpServerResponse{"application/json",
                                   QJsonDocument(body).toJson(QJsonDocument::Compact),
                                   QHttpServerResponse::StatusCode::Ok};
    });

    // Bandwidth test (libSceNpUtility sceNpBandwidthTest*). The client times an upload POST and a
    // fixed 2 MiB download; the payload content is irrelevant.
    m_http->route("/networktest/post", QHttpServerRequest::Method::Post,
                  [](const QHttpServerRequest&) {
                      return QHttpServerResponse(QHttpServerResponse::StatusCode::Ok);
                  });
    // Bandwidth probe. Both titles fetch this once per session to size their netcode, but the
    // route hands out 2 MiB to anyone who asks, so left open it is the cheapest way to pull an
    // unbounded amount of traffic out of the server. One download per address per window is all
    // the probe needs.
    m_http->route("/networktest/get_2m", QHttpServerRequest::Method::Get,
                  [](const QHttpServerRequest& req) -> QHttpServerResponse {
                      static constexpr qint64 kWindowMs = 10'000;
                      static QMutex mutex;
                      static QHash<QString, qint64> lastServed;

                      const QString peer = req.remoteAddress().toString();
                      const qint64 now = QDateTime::currentMSecsSinceEpoch();
                      {
                          QMutexLocker lock(&mutex);
                          // Drop entries that aged out, so a long-running server does not
                          // accumulate one row per address that ever probed it.
                          for (auto it = lastServed.begin(); it != lastServed.end();) {
                              it = (now - it.value() > kWindowMs) ? lastServed.erase(it) : ++it;
                          }
                          const auto it = lastServed.find(peer);
                          if (it != lastServed.end()) {
                              qWarning() << "WebAPI: networktest/get_2m rate limited for" << peer;
                              return QHttpServerResponse{
                                  QHttpServerResponse::StatusCode::TooManyRequests};
                          }
                          lastServed.insert(peer, now);
                      }

                      static const QByteArray payload(2 * 1024 * 1024, '\0');
                      qInfo() << "WebAPI: networktest/get_2m served to" << peer;
                      return QHttpServerResponse{"application/octet-stream", payload,
                                                 QHttpServerResponse::StatusCode::Ok};
                  });

    // user routes
    WebApiRoutes::RegisterUserRoutes(*m_http, *m_db, *m_shared);
    WebApiRoutes::RegisterProfileRoutes(*m_http, *m_db, *m_shared);
    WebApiRoutes::RegisterPresenceRoutes(*m_http, *m_db, *m_shared);
    WebApiRoutes::RegisterSessionRoutes(*m_http, *m_db, *m_shared);
    WebApiRoutes::RegisterIdentityRoutes(*m_http, *m_db);

    m_http->setMissingHandler(
        this, [](const QHttpServerRequest& req, QHttpServerResponder& responder) {
            qWarning() << "WebAPI: unhandled" << req.method() << req.url().path()
                       << "(query:" << req.url().query() << ")";

            QJsonObject errorObj;
            errorObj.insert("code", static_cast<qint64>(0x80920005));
            errorObj.insert("message", QStringLiteral("Endpoint not implemented"));
            QJsonObject body;
            body.insert("error", errorObj);
            responder.sendResponse(QHttpServerResponse{
                "application/json",
                QJsonDocument(body).toJson(QJsonDocument::Compact),
                QHttpServerResponder::StatusCode::NotFound,
            });
        });
}
