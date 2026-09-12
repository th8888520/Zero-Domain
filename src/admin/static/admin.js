(function(){
  // ═══════════════════════════════════════════════════════════
  // 状态管理
  // ═══════════════════════════════════════════════════════════
  var state = {
    token: localStorage.getItem("neural-shield-token") || "",
    logs: [],
    stats: null,
    currentPage: 1,
    pageSize: 30,
    logsPage: 1,
    logsFetchSize: 50,
    logsHasMore: false,
    logsTotal: 0,
    logsLoadingMore: false,
    previousStats: null,
    activeView: "dashboard"
  };

  var $ = function(id) { return document.getElementById(id); };

  // ═══════════════════════════════════════════════════════════
  // API 请求
  // ═══════════════════════════════════════════════════════════
  function authHeaders(extra) {
    var h = Object.assign({ "Accept": "application/json" }, extra || {});
    if (state.token) h.Authorization = "Bearer " + state.token;
    return h;
  }

  async function api(path, options) {
    options = options || {};
    options.headers = authHeaders(Object.assign({ "Content-Type": "application/json" }, options.headers || {}));
    var res = await fetch(path, options);
    var data = await res.json().catch(function() { return {}; });
    if (!res.ok) {
      if (res.status === 401) {
        alert("令牌无效，请重新输入");
        localStorage.removeItem("neural-shield-token");
        state.token = "";
        showTokenInput();
      }
      throw new Error(data.error || ("HTTP " + res.status));
    }
    return data;
  }

  // ═══════════════════════════════════════════════════════════
  // 令牌管理
  // ═══════════════════════════════════════════════════════════
  function showTokenInput() {
    $("token-container").style.display = "flex";
  }

  function hideTokenInput() {
    // 不再隐藏令牌输入框，始终显示
    // $("token-container").style.display = "none";
  }

  function submitToken() {
    var token = $("token-input").value.trim();
    if (!token) {
      alert("请输入管理员令牌");
      return;
    }
    state.token = token;
    localStorage.setItem("neural-shield-token", token);
    $("status-text").textContent = "正在连接...";
    loadData();
  }

  $("token-submit").addEventListener("click", submitToken);
  $("token-input").addEventListener("keypress", function(e) {
    if (e.key === "Enter") {
      submitToken();
    }
  });

  // 始终显示令牌输入框
  showTokenInput();

  // 如果已有令牌，填充到输入框
  if (state.token) {
    $("token-input").value = state.token;
    $("token-input").type = "password"; // 显示为密码
  }

  // ═══════════════════════════════════════════════════════════
  // 数据加载
  // ═══════════════════════════════════════════════════════════
  async function loadData() {
    try {
      $("status-text").textContent = "正在加载...";
      $("status-text").style.color = "var(--text-secondary)";

      // 统计全量；首屏日志分页；仪表盘拦截单独拉 block
      var statsData = await api("/admin/api/audit/stats");
      var auditData = await api("/admin/api/audit?limit=" + state.logsFetchSize + "&offset=0");
      var blockedData = await api("/admin/api/audit?verdict=block&limit=100&offset=0");
      state.stats = statsData;
      state.logsTotal = auditData.total || 0;
      state.logsHasMore = !!auditData.hasMore;
      state.logsPage = 1;
      var byId = {};
      (auditData.records || []).concat(blockedData.records || []).forEach(function(item) {
        if (item && item.id) byId[item.id] = item;
      });
      state.logs = Object.keys(byId).map(function(id) { return byId[id]; }).sort(function(a, b) {
        return String(b.time || "").localeCompare(String(a.time || ""));
      });
      updateStats(state.stats);
      renderLogs();
      if (typeof window.renderLogsView === "function") {
        window.renderLogsView();
      }
      if (state.activeView === "stats") {
        updateStatsView(state.stats);
      }
      if (state.activeView === "config" && typeof window.loadConfigView === "function") {
        window.loadConfigView();
      }

      $("status-text").textContent = "连接成功";
      $("status-text").style.color = "#00ff88";

      setTimeout(function() {
        $("status-text").textContent = "系统在线";
        $("status-text").style.color = "#00ff88";
      }, 3000);
    } catch (err) {
      console.error("加载数据失败:", err);
      $("status-text").textContent = "连接失败 - " + err.message;
      $("status-text").style.color = "#ff4444";
      var logsBody = $("logs-table-body");
      if (logsBody) {
        logsBody.textContent = "";
        var tr = document.createElement("tr");
        var td = document.createElement("td");
        td.colSpan = 7;
        td.style.cssText = "text-align:center;padding:60px;color:var(--text-tertiary);";
        td.textContent = "加载失败: " + (err.message || "未知错误");
        tr.appendChild(td);
        logsBody.appendChild(tr);
      }
    }
  }



  function updateStats(data) {
    if (!data) return;

    // 计算变化趋势
    var trend = "";
    if (state.previousStats && state.previousStats.total > 0) {
      var change = data.total - state.previousStats.total;
      if (change > 0) {
        trend = "较上次 +" + change + " 条";
      } else if (change < 0) {
        trend = "较上次 " + change + " 条";
      } else {
        trend = "无新增";
      }
    } else {
      trend = "首次加载";
    }

    $("total-requests").textContent = data.total || 0;
    $("total-trend").textContent = trend;
    $("allow-count").textContent = data.allow || 0;
    $("block-count").textContent = data.block || 0;
    $("blocked-count").textContent = data.block || 0;

    var allowRate = data.total > 0 ? ((data.allow / data.total) * 100).toFixed(1) : "0.0";
    var blockRate = data.total > 0 ? ((data.block / data.total) * 100).toFixed(1) : "0.0";

    $("allow-rate").textContent = allowRate + "%";
    $("block-rate").textContent = blockRate + "%";

    // 保存当前统计作为下次对比基准
    state.previousStats = data;

    // 计算平均响应时间
    if (state.logs.length > 0) {
      var totalDuration = 0;
      var count = 0;
      state.logs.forEach(function(log) {
        if (log.durationMs) {
          totalDuration += log.durationMs;
          count++;
        }
      });
      var avgMs = count > 0 ? Math.round(totalDuration / count) : 0;
      $("avg-response").textContent = avgMs + "ms";
    } else {
      $("avg-response").textContent = "--";
    }

    // 更新统计分析视图
    if (typeof updateStatsView === 'function') {
      updateStatsView(data);
    }
  }

  function renderLogs() {
    var tbody = $("log-body");
    if (!tbody) return;

    // 仪表盘只显示被拦截的记录
    var blockedLogs = state.logs.filter(function(log) {
      return log.verdict === 'block';
    });

    if (blockedLogs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:60px;color:var(--text-tertiary);">暂无拦截记录</td></tr>';
      updatePagination();
      return;
    }

    // 获取当前页数据
    var start = (state.currentPage - 1) * state.pageSize;
    var end = start + state.pageSize;
    var pageData = blockedLogs.slice(start, end);

    var html = pageData.map(function(log, idx) {
      // 需要找到原始日志数组中的索引
      var globalIdx = state.logs.indexOf(log);
      var reason = log.blockReason || log.reason || '-';
      var row = '<tr style="cursor:pointer;" onclick="showLogDetail(' + globalIdx + ')">';
      row += '<td>' + formatTime(log.time) + '</td>';
      row += '<td><span class="cyber-method">' + escapeHtml(log.method || 'POST') + '</span></td>';
      row += '<td class="col-path" style="font-family:var(--font-mono);font-size:12px;" title="' + escapeAttr(log.path || '-') + '"><span>' + escapeHtml(log.path || '-') + '</span></td>';
      row += '<td>' + getBadge(log.verdict) + '</td>';
      row += '<td>' + escapeHtml(log.upstreamStatus != null ? String(log.upstreamStatus) : '-') + '</td>';
      row += '<td class="col-reason" title="' + escapeAttr(reason) + '"><span>' + escapeHtml(reason) + '</span></td>';
      row += '<td>' + (log.durationMs ? log.durationMs + 'ms' : '-') + '</td>';
      row += '</tr>';
      return row;
    }).join('');

    tbody.innerHTML = html;

    var totalPages = Math.max(1, Math.ceil(blockedLogs.length / state.pageSize));
    var pageInfo = $("page-info");
    if (pageInfo) {
      pageInfo.textContent = "第 " + state.currentPage + " 页 / 共 " + totalPages + " 页";
    }

    $("page-first").disabled = state.currentPage === 1;
    $("page-prev").disabled = state.currentPage === 1;
    $("page-next").disabled = state.currentPage >= totalPages;
    $("page-last").disabled = state.currentPage >= totalPages;
  }

  function getBadge(verdict) {
    var map = {
      'allow': '<span class="cyber-badge allow">放行</span>',
      'block': '<span class="cyber-badge block">拦截</span>',
      'error': '<span class="cyber-badge error">错误</span>'
    };
    return map[verdict] || '<span class="cyber-badge">' + escapeHtml(verdict || '-') + '</span>';
  }

  function formatTime(value) {
    try {
      var d = new Date(value);
      var pad = function(n) { return n < 10 ? '0' + n : n; };
      return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
             pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    } catch (e) {
      return value || "-";
    }
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/'/g, '&#39;');
  }

  function updatePagination() {
    var blockedLogs = state.logs.filter(function(log) { return log.verdict === 'block'; });
    var totalPages = Math.max(1, Math.ceil(blockedLogs.length / state.pageSize));
    var pageInfo = $("page-info");
    if (pageInfo) {
      pageInfo.textContent = "第 " + state.currentPage + " 页 / 共 " + totalPages + " 页";
    }

    $("page-first").disabled = state.currentPage === 1;
    $("page-prev").disabled = state.currentPage === 1;
    $("page-next").disabled = state.currentPage >= totalPages;
    $("page-last").disabled = state.currentPage >= totalPages;
  }

  // ═══════════════════════════════════════════════════════════
  // 分页控制
  // ═══════════════════════════════════════════════════════════
  $("page-first").addEventListener("click", function() {
    state.currentPage = 1;
    renderLogs();
  });

  $("page-prev").addEventListener("click", function() {
    if (state.currentPage > 1) {
      state.currentPage--;
      renderLogs();
    }
  });

  $("page-next").addEventListener("click", function() {
    var blockedLogs = state.logs.filter(function(log) { return log.verdict === 'block'; });
    var totalPages = Math.ceil(blockedLogs.length / state.pageSize);
    if (state.currentPage < totalPages) {
      state.currentPage++;
      renderLogs();
    }
  });

  $("page-last").addEventListener("click", function() {
    var blockedLogs = state.logs.filter(function(log) { return log.verdict === 'block'; });
    state.currentPage = Math.ceil(blockedLogs.length / state.pageSize);
    renderLogs();
  });

  // ═══════════════════════════════════════════════════════════
  // 审计日志视图
  // ═══════════════════════════════════════════════════════════
  window.renderLogsView = function() {
    var tbody = $("logs-table-body");
    if (!tbody) return;

    if (!state.token) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:60px;color:var(--text-tertiary);">请先输入管理员令牌</td></tr>';
      return;
    }

    if (state.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:60px;color:var(--text-tertiary);">暂无数据</td></tr>';
      updateLogsPagination();
      return;
    }

    var start = (state.logsPage - 1) * state.pageSize;
    var end = start + state.pageSize;
    var pageData = state.logs.slice(start, end);

    var html = pageData.map(function(log, idx) {
      var globalIdx = start + idx;
      var reason = log.blockReason || log.reason || '-';
      var row = '<tr style="cursor:pointer;" onclick="showLogDetail(' + globalIdx + ')">';
      row += '<td>' + formatTime(log.time) + '</td>';
      row += '<td><span class="cyber-method">' + (log.method || 'POST') + '</span></td>';
      row += '<td class="col-path" style="font-family:var(--font-mono);font-size:12px;" title="' + escapeAttr(log.path || '-') + '"><span>' + escapeHtml(log.path || '-') + '</span></td>';
      row += '<td>' + getBadge(log.verdict) + '</td>';
      row += '<td>' + (log.upstreamStatus || '-') + '</td>';
      row += '<td>' + (log.durationMs ? log.durationMs + 'ms' : '-') + '</td>';
      row += '<td class="col-reason" title="' + escapeAttr(reason) + '"><span>' + escapeHtml(reason) + '</span></td>';
      row += '</tr>';
      return row;
    }).join('');

    tbody.innerHTML = html;
    updateLogsPagination();
  };

  function updateLogsPagination() {
    var loadedPages = Math.max(1, Math.ceil(state.logs.length / state.pageSize));
    var pageInfo = $("logs-page-info");
    if (pageInfo) {
      pageInfo.textContent = "第 " + state.logsPage + " 页 / 已加载 " + state.logs.length + " / 共 " + (state.logsTotal || state.logs.length) + " 条";
    }

    var firstBtn = $("logs-page-first");
    var prevBtn = $("logs-page-prev");
    var nextBtn = $("logs-page-next");
    var lastBtn = $("logs-page-last");
    var moreBtn = $("logs-load-more-btn");

    if (firstBtn) firstBtn.disabled = state.logsPage === 1;
    if (prevBtn) prevBtn.disabled = state.logsPage === 1;
    if (nextBtn) nextBtn.disabled = state.logsPage >= loadedPages && !state.logsHasMore;
    if (lastBtn) lastBtn.disabled = state.logsPage >= loadedPages && !state.logsHasMore;
    if (moreBtn) {
      moreBtn.style.display = state.logsHasMore ? "inline-flex" : "none";
      moreBtn.disabled = !!state.logsLoadingMore;
      moreBtn.textContent = state.logsLoadingMore ? "加载中..." : "加载更多";
    }
  }

  async function loadMoreLogs() {
    if (!state.token || state.logsLoadingMore || !state.logsHasMore) return;
    state.logsLoadingMore = true;
    updateLogsPagination();
    try {
      var offset = state.logs.length;
      var page = await api("/admin/api/audit?limit=" + state.logsFetchSize + "&offset=" + offset);
      var byId = {};
      state.logs.forEach(function(item) { if (item && item.id) byId[item.id] = item; });
      (page.records || []).forEach(function(item) { if (item && item.id) byId[item.id] = item; });
      state.logs = Object.keys(byId).map(function(id) { return byId[id]; }).sort(function(a, b) {
        return String(b.time || "").localeCompare(String(a.time || ""));
      });
      state.logsTotal = page.total || state.logsTotal;
      state.logsHasMore = !!page.hasMore;
      window.renderLogsView();
    } catch (err) {
      alert("加载更多失败: " + (err.message || "未知错误"));
    } finally {
      state.logsLoadingMore = false;
      updateLogsPagination();
    }
  }

  // 审计日志分页事件
  var logsPageFirst = $("logs-page-first");
  if (logsPageFirst) {
    logsPageFirst.addEventListener("click", function() {
      state.logsPage = 1;
      window.renderLogsView();
    });
  }

  var logsPagePrev = $("logs-page-prev");
  if (logsPagePrev) {
    logsPagePrev.addEventListener("click", function() {
      if (state.logsPage > 1) {
        state.logsPage--;
        window.renderLogsView();
      }
    });
  }

  var logsPageNext = $("logs-page-next");
  if (logsPageNext) {
    logsPageNext.addEventListener("click", async function() {
      var loadedPages = Math.max(1, Math.ceil(state.logs.length / state.pageSize));
      if (state.logsPage < loadedPages) {
        state.logsPage++;
        window.renderLogsView();
        return;
      }
      if (state.logsHasMore) {
        await loadMoreLogs();
        var pages = Math.max(1, Math.ceil(state.logs.length / state.pageSize));
        state.logsPage = pages;
        window.renderLogsView();
      }
    });
  }

  var logsPageLast = $("logs-page-last");
  if (logsPageLast) {
    logsPageLast.addEventListener("click", async function() {
      while (state.logsHasMore && !state.logsLoadingMore) {
        await loadMoreLogs();
      }
      state.logsPage = Math.max(1, Math.ceil(state.logs.length / state.pageSize) || 1);
      window.renderLogsView();
    });
  }

  var logsLoadMoreBtn = $("logs-load-more-btn");
  if (logsLoadMoreBtn) {
    logsLoadMoreBtn.addEventListener("click", function() {
      loadMoreLogs();
    });
  }

  // 审计日志刷新按钮
  var logsRefreshBtn = $("logs-refresh-btn");
  if (logsRefreshBtn) {
    logsRefreshBtn.addEventListener("click", function() {
      if (state.token) {
        loadData();
      } else {
        alert("请先输入管理员令牌");
      }
    });
  }

  var logsClearBtn = $("logs-clear-btn");
  if (logsClearBtn) {
    logsClearBtn.addEventListener("click", function() {
      state.logs = [];
      state.logsPage = 1;
      window.renderLogsView();
      renderLogs();
    });
  }

  // ═══════════════════════════════════════════════════════════
  // 配置管理视图
  // ═══════════════════════════════════════════════════════════
  function setText(id, value) {
    var el = $(id);
    if (el) el.textContent = (value === 0 || value) ? String(value) : "--";
  }

  window.loadConfigView = async function() {
    if (!state.token) {
      setText("config-upstream", "请先输入管理员令牌");
      setText("config-mode", "--");
      setText("config-review", "--");
      return;
    }

    try {
      var config = await api("/admin/api/config");

      setText("config-mode", config.proxyAuthPassthrough ? "透传模式" : "替换模式");
      setText("config-review", config.reviewMode === "llm" ? "开启（硬拦+LLM）" : "关闭（整闸跳过）");
      setText("config-upstream", config.upstreamURL || "--");
      setText("config-upstream-live", config.upstreamURL || "--");
      setText("config-upstream-fallback", config.upstreamFallbackURL || "--");
      var sourceLabel = config.upstreamSource === "ccswitch" ? "ccswitch" : "static";
      var resolvedLabel = config.upstreamResolvedFrom === "ccswitch"
        ? "CCS 实时"
        : (config.upstreamResolvedFrom === "static" ? "static" : "回退 UPSTREAM_URL");
      setText("config-upstream-source", sourceLabel + " / " + resolvedLabel);
      setText("config-upstream-trend", resolvedLabel);
      setText("config-audit-path", config.auditPath || "--");
      setText("config-listen", (config.listenHost || "--") + ":" + (config.listenPort || "--"));
      setText("config-scope", config.reviewScope || "--");
      setText("config-provider", config.judgeProvider || "--");
      setText("config-model", config.judgeModel || "--");
      setText("config-judge-base", config.judgeBaseURL || "--");
      if (config.judgeAPIKeyConfigured) {
        setText("config-review-key", "已配置 ···" + (config.judgeAPIKeySuffix || "****"));
      } else {
        setText("config-review-key", "未配置");
      }
      setText("config-timeout", config.judgeTimeoutMs != null ? (config.judgeTimeoutMs + "ms") : "--");
      setText("config-concurrent", config.judgeMaxConcurrent != null ? config.judgeMaxConcurrent : "--");
      setText("config-interval", config.judgeMinIntervalMs != null ? (config.judgeMinIntervalMs + "ms") : "--");
      setText("config-queue", config.judgeQueueSize != null ? config.judgeQueueSize : "--");
      setText("config-fail-open", config.judgeFailOpen ? "故障放行（不推荐）" : "故障拦截（推荐）");
      setText("config-disconnect", config.disconnectOnBlock ? "开启" : "关闭");
      setText("config-audit-body", config.auditIncludeBody || "--");
      setText("config-audit-stdout", config.auditStdout || "--");
      setText("config-upstream-auth", config.upstreamAuthMode || "--");

      var reminder = $("secrets-reminder");
      if (reminder) {
        var info = config.secretsReminder;
        if (info && info.messages && info.messages.length > 0) {
          var title = info.recommendRotate ? "密钥轮换提醒" : "密钥存放提示";
          reminder.style.display = "block";
          reminder.innerHTML = "<strong>" + escapeHtml(title) + "</strong><br>" +
            info.messages.map(function(line) { return escapeHtml(line); }).join("<br>");
        } else {
          reminder.style.display = "none";
          reminder.textContent = "";
        }
      }
    } catch (err) {
      console.error("加载配置失败:", err);
      setText("config-upstream", "加载失败: " + err.message);
    }
  };

  var configRefreshBtn = $("config-refresh-btn");
  if (configRefreshBtn) {
    configRefreshBtn.addEventListener("click", function() {
      window.loadConfigView();
    });
  }

  // ═══════════════════════════════════════════════════════════
  // .env 在线编辑器
  // ═══════════════════════════════════════════════════════════
  async function loadEnvFile() {
    var status = $("env-status");
    var editor = $("env-editor");
    var warn = $("env-override-warning");
    if (!editor) return;
    try {
      var result = await api("/admin/api/env-file");
      if (!result.exists) {
        status.textContent = "未找到 .env 文件（路径: " + result.path + "），可直接编辑后保存创建";
        editor.value = "";
        warn.style.display = "none";
        return;
      }
      editor.value = result.content;
      var redactNote = result.redacted
        ? "（密钥字段已脱敏为 ***；保存前请勿把 *** 写回，须保留原值或填入新密钥）"
        : "";
      status.textContent = "已加载: " + result.path + redactNote;
      if (result.overriddenKeys && result.overriddenKeys.length > 0) {
        warn.style.display = "block";
        warn.textContent = "⚠ 以下键被管理面板的持久化配置覆盖，修改 .env 不会生效（除非先在覆盖层删除）: " + result.overriddenKeys.join(", ");
      } else {
        warn.style.display = "none";
      }
    } catch (err) {
      status.textContent = "加载失败: " + (err.message || "未知错误");
      status.style.color = "var(--cyber-red)";
    }
  }

  var envReloadBtn = $("env-reload-btn");
  if (envReloadBtn) {
    envReloadBtn.addEventListener("click", function() { loadEnvFile(); });
  }

  var envSaveBtn = $("env-save-btn");
  if (envSaveBtn) {
    envSaveBtn.addEventListener("click", async function() {
      var editor = $("env-editor");
      var status = $("env-status");
      if (!editor) return;
      if (!confirm("确认保存 .env？\n保存前会自动备份，保存后需重启代理生效。")) return;
      try {
        envSaveBtn.disabled = true;
        envSaveBtn.textContent = "保存中...";
        var result = await api("/admin/api/env-file", {
          method: "PUT",
          body: JSON.stringify({ content: editor.value }),
        });
        status.textContent = "✓ 已保存: " + result.path + "（备份: " + result.backupPath + "）";
        status.style.color = "#00ff88";
        alert("保存成功！\n备份: " + result.backupPath + "\n请重启代理使配置生效。");
      } catch (err) {
        status.textContent = "保存失败: " + (err.message || "未知错误");
        status.style.color = "var(--cyber-red)";
        alert("保存失败: " + (err.message || "未知错误"));
      } finally {
        envSaveBtn.disabled = false;
        envSaveBtn.textContent = "保存";
      }
    });
  }

  // 首次加载配置视图时加载 .env
  loadEnvFile();

  // ═══════════════════════════════════════════════════════════
  // 日志详情弹窗
  // ═══════════════════════════════════════════════════════════
  function closeLogDetail() {
    var modal = $("log-detail-modal");
    if (modal) modal.classList.remove("open");
  }

  function formatBlockedBody(body, maxLen) {
    var bodyStr;
    if (typeof body === "string") {
      bodyStr = body;
    } else {
      try {
        // 先紧凑序列化，避免大对象 pretty-print 卡死弹窗
        bodyStr = JSON.stringify(body);
        if (bodyStr.length <= maxLen) {
          bodyStr = JSON.stringify(body, null, 2);
        }
      } catch (e) {
        bodyStr = String(body);
      }
    }
    if (bodyStr.length > maxLen) {
      return bodyStr.slice(0, maxLen) + "...(已截断)";
    }
    return bodyStr;
  }

  function escapeRegExp(value) {
    var special = ".*+?^$()[]{}|\\";
    var out = "";
    var text = String(value);
    for (var i = 0; i < text.length; i++) {
      var ch = text.charAt(i);
      out += special.indexOf(ch) >= 0 ? ("\\" + ch) : ch;
    }
    return out;
  }

  function extractJudgeVerdictLine(raw) {
    if (!raw) return "";
    try {
      var parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      var content = parsed && parsed.choices && parsed.choices[0] && parsed.choices[0].message
        ? parsed.choices[0].message.content
        : "";
      if (typeof content === "string" && content.trim()) {
        return content.trim().split(/\r?\n/)[0].trim();
      }
      if (Array.isArray(content)) {
        var textParts = content.map(function(part) {
          if (typeof part === "string") return part;
          if (part && typeof part.text === "string") return part.text;
          return "";
        }).join("");
        if (textParts.trim()) return textParts.trim().split(/\r?\n/)[0].trim();
      }
    } catch (e) {}
    var text = String(raw);
    var line = text.split(/\r?\n/).find(function(item) {
      return /^(ALLOW|BLOCK|REVIEW)\b/i.test(item.trim());
    });
    // 不回退到原始 JSON 片段，避免把 message/content 等字段名当成高亮词
    return line ? line.trim() : "";
  }

  function extractHighlightNeedles(reason, verdictLine, bodyText) {
    // 审查回包若是 JSON（无法识别的格式），不参与高亮抽词，避免 vulnerabilities 等字段名误标
    var usableVerdict = verdictLine && !/^\s*[{\[]/.test(verdictLine) ? verdictLine : "";
    var source = [reason || "", usableVerdict].join(" ");
    var needles = [];
    var seen = {};
    function pushNeedle(value) {
      var text = String(value || "").trim().replace(/^["']+|["']+$/g, "");
      if (text.length < 2 || text.length > 80) return;
      if (/^(BLOCK|REVIEW|ALLOW|assistant|user|system|content|message|messages|role|model|type|text|tool|result|function|error|需要|人工|确认|可能|涉及|存在|请求|内容|具体|原因|方案)$/i.test(text)) return;
      if (seen[text]) return;
      seen[text] = true;
      needles.push(text);
    }

    var quoteRe = /[「『"']([^「」『』"']{2,80})[」』"']/g;
    var quoteMatch;
    while ((quoteMatch = quoteRe.exec(source))) {
      pushNeedle(quoteMatch[1]);
    }

    // 只认引号摘录 + 固定危险命令，避免概括词大面积误高亮
    [
      "rm -rf", "del /f", "DROP TABLE", "DROP DATABASE", "TRUNCATE",
      "systemctl stop", "systemctl restart", "shutdown", "reboot", "kill -9"
    ].forEach(function(pattern) {
      if (source.indexOf(pattern) !== -1 || (bodyText && bodyText.indexOf(pattern) !== -1)) {
        pushNeedle(pattern);
      }
    });

    return needles.sort(function(a, b) { return b.length - a.length; }).slice(0, 12);
  }

  function highlightBlockedText(text, needles) {
    var escaped = escapeHtml(text).replace(/\n/g, "<br>");
    var hitCount = 0;
    needles.forEach(function(needle) {
      var escapedNeedle = escapeHtml(needle);
      if (!escapedNeedle || escaped.indexOf(escapedNeedle) === -1) return;
      var re = new RegExp(escapeRegExp(escapedNeedle), "g");
      escaped = escaped.replace(re, function(match) {
        hitCount += 1;
        return '<mark class="blocked-hit">' + match + '</mark>';
      });
    });
    return { html: escaped, hitCount: hitCount };
  }

  function renderDetailRows(rows, options) {
    options = options || {};
    return rows.map(function(pair) {
      var key = pair[0];
      var value = pair[1];
      var isBlockedBody = key === "被拦截内容";
      var rowClass = "cyber-modal-row" + (isBlockedBody ? " blocked-body-row" : "");
      var keyHtml = escapeHtml(key) + (isBlockedBody ? '<span class="blocked-body-badge">BLOCKED</span>' : "");

      if (isBlockedBody && options.blockedHtml) {
        var meta = options.hitCount > 0
          ? '<div class="blocked-hit-meta">已标记 ' + options.hitCount + ' 处与拦截原因相关的原文</div>'
          : '<div class="blocked-hit-meta">未能精确定位命中片段，已整段标记为拦截原文（审查理由多为概括，未必逐字出现在请求体中）</div>';
        return '<div class="' + rowClass + '"><div class="cyber-modal-key">' + keyHtml +
          '</div><div class="cyber-modal-val"><div class="blocked-body-box">' + options.blockedHtml +
          '</div>' + meta + '</div></div>';
      }

      var escaped = escapeHtml(String(value)).replace(/\n/g, "<br>");
      return '<div class="' + rowClass + '"><div class="cyber-modal-key">' + keyHtml +
        '</div><div class="cyber-modal-val">' + escaped + '</div></div>';
    }).join("");
  }

  window.showLogDetail = async function(idx) {
    var log = state.logs[idx];
    if (!log) return;

    var body = $("log-detail-body");
    var modal = $("log-detail-modal");
    if (!body || !modal) return;

    var title = $("log-detail-modal").querySelector(".cyber-modal-title");
    if (title) {
      title.textContent = log.verdict === "block" ? "拦截详情" : "审计详情";
    }

    // 列表默认无 body：拦截详情按 id 再拉一次
    if (log.verdict === "block" && log.id && (log.requestBody == null || log.requestBody === "")) {
      try {
        var detail = await api("/admin/api/audit?id=" + encodeURIComponent(log.id));
        if (detail && detail.record) {
          log = Object.assign({}, log, detail.record);
          state.logs[idx] = log;
        }
      } catch (e) {}
    }

    var reason = log.reason || log.blockReason || "-";
    var verdictLine = extractJudgeVerdictLine(log.judgeRaw);
    var rows = [
      ["时间", formatTime(log.time)],
      ["方法", log.method || "-"],
      ["路径", log.path || "-"],
      ["判定", log.verdict || "-"],
      ["结果", log.outcome || "-"],
      ["上游状态", log.upstreamStatus != null ? log.upstreamStatus : "-"],
      ["耗时", log.durationMs != null ? (log.durationMs + "ms") : "-"],
      ["原因", reason],
      ["审查模型", log.judgeModel || "-"],
      ["审查提供商", log.judgeProvider || "-"],
      ["目标", log.requestTarget || "-"]
    ];

    if (log.verdict === "block" && verdictLine) {
      rows.push(["审查判定", verdictLine]);
    }

    var blockedHtml = "";
    var hitCount = 0;
    if (log.verdict === "block") {
      if (log.requestBody != null && log.requestBody !== "") {
        // 服务端已截断，客户端不再二次砍头
        var bodyText = typeof log.requestBody === "string"
          ? log.requestBody
          : (function() { try { return JSON.stringify(log.requestBody, null, 2); } catch (e) { return String(log.requestBody); } })();
        var needles = extractHighlightNeedles(reason, verdictLine, bodyText);
        var highlighted = highlightBlockedText(bodyText, needles);
        blockedHtml = highlighted.html;
        hitCount = highlighted.hitCount;
        rows.push(["被拦截内容", bodyText]);
      } else {
        rows.push(["被拦截内容", "（审计未保存请求体。请确认 AUDIT_INCLUDE_BODY=blocked 或 all，且该条记录产生于配置生效之后）"]);
      }
    }

    body.innerHTML = renderDetailRows(rows, { blockedHtml: blockedHtml, hitCount: hitCount });
    modal.classList.add("open");
  };

  var logDetailClose = $("log-detail-close");
  if (logDetailClose) {
    logDetailClose.addEventListener("click", closeLogDetail);
  }
  var logDetailModal = $("log-detail-modal");
  if (logDetailModal) {
    logDetailModal.addEventListener("click", function(e) {
      if (e.target === logDetailModal) closeLogDetail();
    });
  }
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closeLogDetail();
  });

  // ═══════════════════════════════════════════════════════════
  // 统计分析视图
  // ═══════════════════════════════════════════════════════════
  function updateStatsView(data) {
    if (!data) return;

    var allowEl = $("stats-allow-count");
    var blockEl = $("stats-block-count");
    var skipEl = $("stats-skip-count");

    if (allowEl) allowEl.textContent = data.allow || 0;
    if (blockEl) blockEl.textContent = data.block || 0;
    if (skipEl) skipEl.textContent = data.skipped || 0;

    // 计算百分比
    var total = data.total || 0;
    var allowPercent = total > 0 ? ((data.allow / total) * 100).toFixed(1) : '0.0';
    var blockPercent = total > 0 ? ((data.block / total) * 100).toFixed(1) : '0.0';
    var skipPercent = total > 0 ? ((data.skipped / total) * 100).toFixed(1) : '0.0';

    var allowPercentEl = $("stats-allow-percent");
    var blockPercentEl = $("stats-block-percent");
    var skipPercentEl = $("stats-skip-percent");

    if (allowPercentEl) allowPercentEl.textContent = allowPercent + '%';
    if (blockPercentEl) blockPercentEl.textContent = blockPercent + '%';
    if (skipPercentEl) skipPercentEl.textContent = skipPercent + '%';

    // 简单的活动统计
    var activityBody = $("stats-activity-body");
    if (activityBody && state.logs.length > 0) {
      var now = new Date();
      var last5min = state.logs.filter(function(log) {
        return new Date(log.time) > new Date(now - 5 * 60 * 1000);
      });
      var last15min = state.logs.filter(function(log) {
        return new Date(log.time) > new Date(now - 15 * 60 * 1000);
      });
      var last1hour = state.logs.filter(function(log) {
        return new Date(log.time) > new Date(now - 60 * 60 * 1000);
      });

      var html = '';
      [
        { label: '最近 5 分钟', data: last5min },
        { label: '最近 15 分钟', data: last15min },
        { label: '最近 1 小时', data: last1hour }
      ].forEach(function(item) {
        var total = item.data.length;
        var allow = item.data.filter(function(l) { return l.verdict === 'allow'; }).length;
        var block = item.data.filter(function(l) { return l.verdict === 'block'; }).length;
        var rate = total > 0 ? ((allow / total) * 100).toFixed(1) : '0.0';
        var avgDur = 0;
        if (total > 0) {
          var sumDur = 0;
          var count = 0;
          item.data.forEach(function(l) {
            if (l.durationMs) {
              sumDur += l.durationMs;
              count++;
            }
          });
          avgDur = count > 0 ? Math.round(sumDur / count) : 0;
        }
        html += '<tr><td>' + item.label + '</td><td>' + total + '</td><td>' + allow + '</td><td>' + block + '</td><td>' + rate + '%</td><td>' + avgDur + 'ms</td></tr>';
      });
      activityBody.innerHTML = html || '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-tertiary);">无数据</td></tr>';
    } else if (activityBody) {
      activityBody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-tertiary);">无数据</td></tr>';
    }
  }

  // ═══════════════════════════════════════════════════════════
  // 刷新按钮
  // ═══════════════════════════════════════════════════════════
  var refreshBtn = $("refresh-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", function() {
      if (!state.token) {
        alert("请先输入管理员令牌");
        showTokenInput();
      } else {
        loadData();
      }
    });
  }

  // ═══════════════════════════════════════════════════════════
  // 时钟更新
  // ═══════════════════════════════════════════════════════════
  function updateClock() {
    var now = new Date();
    var timeEl = $('clock-time');
    var dateEl = $('clock-date');

    if (timeEl) {
      var h = now.getHours();
      var m = now.getMinutes();
      var s = now.getSeconds();
      timeEl.textContent = (h < 10 ? '0' + h : h) + ':' + (m < 10 ? '0' + m : m) + ':' + (s < 10 ? '0' + s : s);
    }
    if (dateEl) {
      var year = now.getFullYear();
      var month = now.getMonth() + 1; // 月份从0开始，需要+1
      var day = now.getDate();
      // 格式化为 YYYY MM DD，月份和日期补零
      dateEl.textContent = year + ' ' + (month < 10 ? '0' + month : month) + ' ' + (day < 10 ? '0' + day : day);
    }
  }

  updateClock();
  setInterval(updateClock, 1000);

  // ═══════════════════════════════════════════════════════════
  // 导航切换
  // ═══════════════════════════════════════════════════════════
  var navItems = document.querySelectorAll('.cyber-nav-item');
  var views = document.querySelectorAll('[id^="view-"]');

  function switchView(targetView) {
    if (!targetView) return;
    state.activeView = targetView;

    navItems.forEach(function(nav) {
      nav.classList.toggle('active', nav.getAttribute('data-view') === targetView);
    });

    views.forEach(function(view) {
      view.style.display = 'none';
      view.classList.remove('active');
    });

    var target = document.getElementById('view-' + targetView);
    if (!target) return;

    target.style.display = 'block';
    target.classList.add('active', 'animate-in');

    if (targetView === 'logs') {
      if (!state.token) {
        var tbody = $("logs-table-body");
        if (tbody) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:60px;color:var(--text-tertiary);">请先输入管理员令牌</td></tr>';
        }
      } else if (!state.logs.length) {
        loadData();
      } else {
        window.renderLogsView();
      }
    } else if (targetView === 'config') {
      window.loadConfigView();
    } else if (targetView === 'stats') {
      if (state.stats) {
        updateStatsView(state.stats);
      } else if (state.token) {
        loadData();
      }
    } else if (targetView === 'dashboard') {
      renderLogs();
    }
  }

  navItems.forEach(function(item) {
    item.addEventListener('click', function(e) {
      e.preventDefault();
      switchView(item.getAttribute('data-view'));
    });
  });

  var viewAllBtn = $("view-all-btn");
  if (viewAllBtn) {
    viewAllBtn.addEventListener("click", function() {
      switchView("logs");
    });
  }

  // ═══════════════════════════════════════════════════════════
  // 初始化加载
  // ═══════════════════════════════════════════════════════════
  if (state.token) {
    loadData();
  }

  // 自动刷新（每 15 秒；页面不可见时跳过）
  setInterval(function() {
    if (state.token && document.visibilityState === 'visible') {
      loadData();
    }
  }, 15000);

  console.log('%c[ZERO-DOMAIN] %c系统已初始化',
    'color: #ff6b35; font-weight: bold',
    'color: #00e5ff');
})();
