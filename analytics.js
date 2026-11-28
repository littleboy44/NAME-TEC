
(() => {
  const SITE_SLUG =
    document.currentScript?.dataset.site || "name-tec";

  const API_URL =
    "https://name-tec-server.onrender.com/api/analytics/track";

  function createId() {
    return crypto.randomUUID();
  }

  function getStoredId(storage, key) {
    try {
      let id = storage.getItem(key);

      if (!id) {
        id = createId();
        storage.setItem(key, id);
      }

      return id;
    } catch {
      return createId();
    }
  }

  const visitorId = getStoredId(
    localStorage,
    `nametec_visitor_${SITE_SLUG}`
  );

  const sessionId = getStoredId(
    sessionStorage,
    `nametec_session_${SITE_SLUG}`
  );

  function track(eventType) {
    if (document.visibilityState === "hidden") return;

    fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        siteSlug: SITE_SLUG,
        visitorId,
        sessionId,
        path: location.pathname,
        eventType
      }),
      keepalive: true
    }).catch(() => {});
  }

  // 페이지 조회 기록
  track("pageview");

  // 1분마다 접속 상태 갱신
  setInterval(() => {
    track("heartbeat");
  }, 60000);

  // 다시 페이지를 볼 때 접속 상태 갱신
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      track("heartbeat");
    }
  });
})();
