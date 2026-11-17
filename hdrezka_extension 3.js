(function () {
    'use strict';

    // HDRezka Extension 0.3.6 - direct authentication using the Online_Mod request pattern

    if (window.__hdrezka_extension_loaded) return;
    window.__hdrezka_extension_loaded = true;

    var L = window.Lampa;
    var HOST = '';
    var REQ = null;
    var USER_AGENT = 'Mozilla/5.0 (Linux; Android 10; Android TV) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
    var SESSION_COOKIE = '';

    function notify(message) {
        if (L && L.Noty && L.Noty.show) L.Noty.show(String(message || 'Ошибка HDRezka'));
        else console.log('[HDRezka]', message);
    }

    function storage(key, fallback) {
        try {
            var value = L.Storage.get(key, fallback);
            return value === undefined || value === null || value === '' ? fallback : value;
        } catch (e) {
            return fallback;
        }
    }

    function host() {
        if (HOST) return HOST;
        var mirror = String(storage('hdrezka_auth_mirror', 'https://rezka.ag')).trim();
        if (!/^https?:\/\//i.test(mirror)) mirror = 'https://' + mirror;
        HOST = mirror.replace(/\/+$/, '');
        return HOST;
    }

    function base64(value) {
        return btoa(unescape(encodeURIComponent(String(value || ''))));
    }

    function proxyBase(name) {
        var custom = L.Storage.field('hdrezka_auth_custom_proxy') === true;
        var customUrl = custom ? String(L.Storage.field('hdrezka_auth_proxy_url') || '') : ''; 
        var proxy1 = (new Date().getHours() % 2) ? 'https://cors.nb557.workers.dev/' : 'https://cors.fx666.workers.dev/';
        var useRezkaProxy = L.Storage.field('hdrezka_auth_use_proxy') === true;
        if (name === 'cookie') return (customUrl || proxy1);
        if (custom && customUrl) return customUrl.replace(/\/+$/, '') + '/';
        if (useRezkaProxy) return proxy1;
        return '';
    }

    function proxyUrl(url, proxy, extra) {
        if (!proxy) return url;
        var name = String(url).replace(/^https?:\/\//, '').split('/').pop().split('?')[0];
        name = name.replace(/\.(php|asp|aspx|jsp|jspx|cgi|pl|py|rb|env|ini|conf|config|htaccess|htpasswd|git|yml|yaml|sql)$/, '.txt');
        return proxy + 'enc2/' + encodeURIComponent(base64(String(extra || '') + url)) + '/' + name + '?jacred.test';
    }

    function androidCanReturnHeaders() {
        try {
            if (typeof AndroidJS === 'undefined' || !AndroidJS.appVersion) return false;
            var parts = String(AndroidJS.appVersion()).split('-');
            return parseInt(parts.pop(), 10) >= 339;
        } catch (e) { return false; }
    }

    function authHeaders(cookie) {
        var h = {
            Origin: host(),
            Referer: host() + '/',
            'User-Agent': USER_AGENT
        };
        if (cookie) h.Cookie = cookie;
        return h;
    }

    function currentCookie() {
        var cookie = String(storage('hdrezka_auth_cookie', '') || '');
        if (cookie && cookie.indexOf('PHPSESSID=') < 0) {
            var sid = SESSION_COOKIE || ('PHPSESSID=' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2));
            SESSION_COOKIE = sid;
            cookie = sid + '; ' + cookie;
        }
        return cookie;
    }

    function headers() {
        return authHeaders(currentCookie());
    }

    function proxiedSiteUrl(url) {
        var proxy = proxyBase('rezka2');
        if (!proxy) return url;
        var cookie = currentCookie();
        var extra = 'param/Origin=' + encodeURIComponent(host()) + '/';
        extra += 'param/Referer=' + encodeURIComponent(host() + '/') + '/';
        extra += 'param/User-Agent=' + encodeURIComponent(USER_AGENT) + '/';
        if (cookie) extra += 'param/Cookie=' + encodeURIComponent(cookie) + '/';
        return proxyUrl(url, proxy, extra);
    }

    function request(url, data, success, fail) {
        if (!REQ) REQ = new L.Reguest();
        REQ.clear();
        REQ.timeout(15000);
        REQ.native(proxiedSiteUrl(url), success, function (a, c) {
            if (fail) fail(a, c);
            else notify(REQ.errorDecode ? REQ.errorDecode(a, c) : 'Не удалось обратиться к HDRezka');
        }, data || false, {
            dataType: data ? 'json' : 'text',
            withCredentials: false,
            headers: headers()
        });
    }

    function post(url, body, success, fail, type) {
        if (!REQ) REQ = new L.Reguest();
        REQ.clear();
        REQ.timeout(15000);
        REQ.native(proxiedSiteUrl(url), success, function (a, c) {
            if (fail) fail(a, c);
            else notify(REQ.errorDecode ? REQ.errorDecode(a, c) : 'Ошибка запроса HDRezka');
        }, body, {
            dataType: type || 'json',
            withCredentials: false,
            headers: headers()
        });
    }

    var AUTH_REQ = null;
    function parseSetCookies(response, previous) {
        var values = {};
        String(previous || '').split(/;\s*/).forEach(function (part) {
            var pos = part.indexOf('=');
            if (pos > 0) values[part.substring(0, pos)] = part.substring(pos + 1);
        });
        var list = response && response.headers && response.headers['set-cookie'];
        if (list && typeof list.forEach === 'function') {
            list.forEach(function (line) {
                var part = String(line).split(';')[0];
                var pos = part.indexOf('=');
                if (pos > 0) {
                    var key = part.substring(0, pos).trim();
                    var val = part.substring(pos + 1).trim();
                    if (val === 'deleted') delete values[key];
                    else values[key] = val;
                }
            });
        }
        return Object.keys(values).map(function (key) { return key + '=' + values[key]; }).join('; ');
    }

    function responseBody(response) {
        var body = response && response.body !== undefined ? response.body : response;
        if (typeof body === 'string') {
            try { return JSON.parse(body); } catch (e) { return body; }
        }
        return body || {};
    }

    // Authentication follows Online_Mod's rezka2Login() transport:
    // Reguest.silent + withCredentials, without forcing the native/proxy path.
    function authProxySettings() {
        return {proxy: '', extra: '', returnHeaders: false};
    }

    function authNative(url, body, success, fail) {
        if (!AUTH_REQ) AUTH_REQ = new L.Reguest();
        AUTH_REQ.clear();
        AUTH_REQ.timeout(15000);

        var options = {
            withCredentials: true
        };
        if (body) options.dataType = 'json';
        else options.dataType = 'text';

        if (typeof AUTH_REQ.silent !== 'function') {
            if (fail) fail('Reguest.silent недоступен в этой сборке Lampa');
            else notify('В этой сборке Lampa недоступен запрос авторизации.');
            return;
        }

        AUTH_REQ.silent(url, function (response) {
            if (success) success(response, authProxySettings());
        }, function (a, c) {
            if (fail) fail(a, c);
            else notify(AUTH_REQ.errorDecode ? AUTH_REQ.errorDecode(a, c) : 'Ошибка авторизации HDRezka');
        }, body || false, options);
    }

    function saveAuthCookie(response, fallback) {
        var cookie = parseSetCookies(response, fallback || '');
        if (cookie) {
            // Оригинальный модуль хранит cookies авторизации без PHPSESSID.
            cookie = cookie.split(/;\s*/).filter(function (part) { return !/^PHPSESSID=/i.test(part); }).join('; ');
            L.Storage.set('hdrezka_auth_cookie', cookie);
        }
        return cookie;
    }

    function authRequired(html) {
        return /<form[^>]+(?:id=["'](?:check-form|loginForm)["']|action=["']\/ajax\/login\/["'])/i.test(String(html || ''));
    }

    function mirrorChallenge(html) {
        var match = String(html || '').match(/<button[^>]+onclick=["']\$\.cookie\(([^)]*)\)/i);
        if (!match) return null;
        var args = match[1];
        var pair = args.match(/^\s*(["'])(.*?)\1\s*,\s*(["'])(.*?)\3/s);
        if (!pair) return null;
        function unquote(value, quote) {
            if (quote === '"') {
                try { return JSON.parse('"' + value.replace(/\\"/g, '\\"') + '"'); } catch (e) {}
            }
            return value.replace(/\\(['"\\])/g, '$1');
        }
        return {name: unquote(pair[2], pair[1]), value: unquote(pair[4], pair[3])};
    }

    function applyMirrorChallenge(html, callback) {
        var pair = mirrorChallenge(html);
        if (!pair || !pair.name) return false;
        var cookie = String(storage('hdrezka_auth_cookie', '') || '');
        var parts = cookie.split(/;\s*/).filter(function (part) {
            return part && part.split('=')[0] !== pair.name;
        });
        parts.push(pair.name + '=' + pair.value);
        L.Storage.set('hdrezka_auth_cookie', parts.join('; '));
        if (callback) callback();
        return true;
    }

    function ensureAuthorization(done) {
        var stored = String(storage('hdrezka_auth_cookie', '') || '');
        var login = String(storage('hdrezka_auth_login', '') || '');
        var password = String(storage('hdrezka_auth_password', '') || '');

        function verifyOrLogin() {
            authNative(host() + '/', false, function (response) {
                var body = responseBody(response);
                var html = typeof body === 'string' ? body : String(body && body.body || '');
                saveAuthCookie(response, stored);
                if (applyMirrorChallenge(html, function () {
                    authNative(host() + '/', false, function (retryResponse) {
                        var retryBody = responseBody(retryResponse);
                        var retryHtml = typeof retryBody === 'string' ? retryBody : String(retryBody && retryBody.body || '');
                        saveAuthCookie(retryResponse, String(storage('hdrezka_auth_cookie', '') || ''));
                        if (!authRequired(retryHtml) && !mirrorChallenge(retryHtml)) done();
                        else doLogin();
                    }, function () { doLogin(); });
                })) return;
                if (!authRequired(html)) return done();
                doLogin();
            }, function () {
                if (login && password) doLogin();
                else {
                    L.Storage.set('hdrezka_auth_status', 'false');
                    notify('Не удалось проверить сессию HDRezka. Проверь зеркало и подключение.');
                }
            });
        }

        function doLogin() {
            if (!login || !password) {
                L.Storage.set('hdrezka_auth_status', 'false');
                notify('Укажи логин и пароль в разделе Настройки → HDRezka, затем нажми «Войти / проверить авторизацию».');
                return;
            }
            var postdata = 'login_name=' + encodeURIComponent(login) +
                '&login_password=' + encodeURIComponent(password) + '&login_not_save=0';
            authNative(host() + '/ajax/login/', postdata, function (response) {
                var body = responseBody(response);
                if (typeof body === 'string') {
                    try { body = JSON.parse(body); } catch (e) { body = {}; }
                }
                if (!body || (!body.success && body.message !== 'Уже авторизован на сайте. Необходимо обновить страницу!')) {
                    L.Storage.set('hdrezka_auth_status', 'false');
                    notify(body && body.message ? body.message : 'HDRezka не приняла логин и пароль.');
                    return;
                }
                var cookie = saveAuthCookie(response, stored);
                L.Storage.set('hdrezka_auth_status', 'true');
                // Проверяем авторизованную главную страницу и сохраняем cookies, выставленные редиректом/проверкой зеркала.
                authNative(host() + '/', false, function (checkResponse) {
                    var checkBody = responseBody(checkResponse);
                    var html = typeof checkBody === 'string' ? checkBody : String(checkBody && checkBody.body || '');
                    saveAuthCookie(checkResponse, cookie);
                    if (applyMirrorChallenge(html, function () {
                        authNative(host() + '/', false, function (retryResponse) {
                            var retryBody = responseBody(retryResponse);
                            var retryHtml = typeof retryBody === 'string' ? retryBody : String(retryBody && retryBody.body || '');
                            saveAuthCookie(retryResponse, String(storage('hdrezka_auth_cookie', '') || ''));
                            if (authRequired(retryHtml) || mirrorChallenge(retryHtml)) {
                                L.Storage.set('hdrezka_auth_status', 'false');
                                notify('Не удалось пройти проверку зеркала HDRezka.');
                            } else done();
                        }, function () { notify('Не удалось подтвердить cookie зеркала HDRezka.'); });
                    })) return;
                    if (authRequired(html)) {
                        L.Storage.set('hdrezka_auth_status', 'false');
                        notify('HDRezka снова требует вход. Проверь зеркало сайта и настройки прокси.');
                        return;
                    }
                    done();
                }, function () {
                    // Успешный AJAX-login уже подтверждён сервером.
                    done();
                });
            }, function () {
                L.Storage.set('hdrezka_auth_status', 'false');
                notify('Не удалось выполнить вход на HDRezka. Проверь соединение и прокси.');
            });
        }

        if (stored) verifyOrLogin();
        else doLogin();
    }

    function cleanTitle(value) {
        return String(value || '')
            .replace(/\([^)]*\)/g, ' ')
            .replace(/[^\p{L}\p{N}]+/gu, ' ')
            .trim().toLowerCase();
    }

    function movieTitle(card) {
        return card.title || card.name || card.original_title || card.original_name || '';
    }

    function releaseYear(card) {
        var date = card.release_date || card.first_air_date || card.last_air_date || '';
        var match = String(date).match(/\d{4}/);
        return match ? parseInt(match[0], 10) : 0;
    }

    function parseSearch(html, card) {
        var found = [];
        var chunks = String(html || '').match(/<li><a href=.*?<\/li>/g) || [];
        var target = cleanTitle(movieTitle(card));
        var year = releaseYear(card);

        chunks.forEach(function (chunk) {
            var box = $('<div></div>').html(chunk);
            var a = box.find('a').first();
            var href = a.attr('href');
            var title = a.text().trim();
            var fullText = box.text().trim();
            var y = (fullText.match(/\b(19\d{2}|20\d{2})\b/) || [])[1];
            if (!href) return;
            if (href.indexOf('http') !== 0) href = host() + (href.charAt(0) === '/' ? '' : '/') + href;
            found.push({
                title: title || fullText || href,
                href: href,
                year: y ? parseInt(y, 10) : 0,
                score: 0
            });
        });

        found.forEach(function (item) {
            var normalized = cleanTitle(item.title);
            if (normalized === target) item.score += 100;
            else if (normalized.indexOf(target) >= 0 || target.indexOf(normalized) >= 0) item.score += 50;
            if (year && item.year) {
                if (year === item.year) item.score += 40;
                else if (Math.abs(year - item.year) <= 1) item.score += 15;
                else item.score -= 30;
            }
        });

        found.sort(function (a, b) { return b.score - a.score; });
        return found;
    }

    function parsePage(html) {
        var text = String(html || '').replace(/\n/g, '');
        var series = text.match(/\.initCDNSeriesEvents\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,/);
        var movie = text.match(/\.initCDNMoviesEvents\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,/);
        var data = {
            isSeries: !!series,
            filmId: series ? series[1] : movie ? movie[1] : '',
            favs: '',
            voices: [],
            seasons: [],
            episodes: [],
            defaultSeason: series ? series[3] : '',
            defaultEpisode: series ? series[4] : ''
        };

        var dom = $('<div></div>').html(text);
        var fav = text.match(/<input type="hidden" id="ctrl_favs" value="([^"]*)"/);
        if (fav) data.favs = fav[1];

        dom.find('#translators-list .b-translator__item').each(function () {
            var el = $(this);
            var name = (el.attr('title') || el.text() || '').trim();
            el.find('img').each(function () {
                var lang = ($(this).attr('title') || $(this).attr('alt') || '').trim();
                if (lang && name.indexOf(lang) < 0) name += ' (' + lang + ')';
            });
            data.voices.push({
                name: name || 'Озвучка',
                id: el.attr('data-translator_id'),
                camrip: el.attr('data-camrip') || '0',
                ads: el.attr('data-ads') || '0',
                director: el.attr('data-director') || '0'
            });
        });

        if (!data.voices.length) {
            if (series) data.voices.push({name: 'Оригинал', id: series[2], camrip: '0', ads: '0', director: '0'});
            else if (movie) data.voices.push({name: 'Оригинал', id: movie[2], camrip: movie[3], ads: movie[4], director: movie[5]});
        }

        dom.find('#simple-seasons-tabs .b-simple_season__item').each(function () {
            data.seasons.push({name: $(this).text().trim(), id: $(this).attr('data-tab_id')});
        });
        dom.find('#simple-episodes-tabs .b-simple_episode__item').each(function () {
            data.episodes.push({
                name: $(this).text().trim(),
                seasonId: $(this).attr('data-season_id'),
                episodeId: $(this).attr('data-episode_id')
            });
        });

        if (data.isSeries && !data.seasons.length && data.defaultSeason) {
            data.seasons.push({name: 'Сезон ' + data.defaultSeason, id: data.defaultSeason});
        }
        if (data.isSeries && !data.episodes.length && data.defaultEpisode) {
            data.episodes.push({
                name: 'Серия ' + data.defaultEpisode,
                seasonId: data.defaultSeason,
                episodeId: data.defaultEpisode
            });
        }
        return data;
    }

    function parseEpisodes(json) {
        var result = {seasons: [], episodes: []};
        var seasons = $('<ul></ul>').html(json && json.seasons || '');
        seasons.find('.b-simple_season__item').each(function () {
            result.seasons.push({name: $(this).text().trim(), id: $(this).attr('data-tab_id')});
        });
        var episodes = $('<div></div>').html(json && json.episodes || '');
        episodes.find('.b-simple_episode__item').each(function () {
            result.episodes.push({
                name: $(this).text().trim(),
                seasonId: $(this).attr('data-season_id'),
                episodeId: $(this).attr('data-episode_id')
            });
        });
        return result;
    }

    function decodeStream(value) {
        if (!value || value.charAt(0) !== '#') return value || '';
        function decode64(str) {
            return decodeURIComponent(atob(str).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        }
        function encode64(str) {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (_, p1) {
                return String.fromCharCode(parseInt(p1, 16));
            }));
        }
        var x = value.substring(2);
        ['$$!!@$$@^!@#$$@', '@@@@@!##!^^^', '####^!!##!@@', '^^^!@##!!##', '$$#!!@#!@##'].forEach(function (trash) {
            x = x.replace('//_//' + encode64(trash), '');
        });
        try { return decode64(x); } catch (e) { return ''; }
    }

    function parsePlaylist(str) {
        var list = [];
        if (!str || str.charAt(0) !== '[') return list;
        try {
            str.substring(1).split(/, *\[/).forEach(function (part) {
                part = part.trim().replace(/,$/, '').trim();
                var end = part.indexOf(']');
                if (end < 0) return;
                var label = part.substring(0, end).trim();
                var tail = part.substring(end + 1).trim();
                if (tail.charAt(0) === '{') {
                    tail.substring(1).split(/; *\{/).forEach(function (voicePart) {
                        var voiceEnd = voicePart.indexOf('}');
                        if (voiceEnd < 0) return;
                        var urls = voicePart.substring(voiceEnd + 1).split(' or ').map(function (u) { return u.trim(); }).filter(Boolean);
                        if (urls.length) list.push({label: label, voice: voicePart.substring(0, voiceEnd).trim(), links: urls});
                    });
                } else {
                    var links = tail.split(' or ').map(function (u) { return u.trim(); }).filter(Boolean);
                    if (links.length) list.push({label: label, links: links});
                }
            });
        } catch (e) {}
        return list;
    }

    function qualityList(json) {
        var decoded = decodeStream(json && json.url || '');
        var items = parsePlaylist(decoded).map(function (item) {
            var links = item.links || [];
            var mp4 = links.filter(function (url) { return /\.mp4(?:$|[?#])/i.test(url); });
            var url = (mp4.length ? mp4[0] : links[0]) || '';
            if (url.indexOf('//') === 0) url = 'https:' + url;
            return {label: item.label, url: url, score: (item.label.match(/(\d{3,4})/) || [])[1] * 1 || 0};
        }).filter(function (item) { return item.url; });
        items.sort(function (a, b) { return b.score - a.score; });
        if (!items.length && decoded && /^https?:\/\//i.test(decoded)) items.push({label: 'Доступное качество', url: decoded, score: 0});
        return items;
    }

    function fetchEpisodes(state, voice, done) {
        var body = 'id=' + encodeURIComponent(state.page.filmId) +
            '&translator_id=' + encodeURIComponent(voice.id) +
            '&favs=' + encodeURIComponent(state.page.favs) +
            '&action=get_episodes';
        post(host() + '/ajax/get_cdn_series/?t=' + Date.now(), body, function (json) {
            done(parseEpisodes(json));
        }, function () {
            notify('Не удалось получить сезоны и серии HDRezka');
        });
    }

    function fetchStream(state, voice, episode, done) {
        var body = 'id=' + encodeURIComponent(state.page.filmId);
        if (state.page.isSeries) {
            body += '&translator_id=' + encodeURIComponent(voice.id);
            body += '&season=' + encodeURIComponent(episode.seasonId);
            body += '&episode=' + encodeURIComponent(episode.episodeId);
            body += '&favs=' + encodeURIComponent(state.page.favs);
            body += '&action=get_stream';
        } else {
            body += '&translator_id=' + encodeURIComponent(voice.id);
            body += '&is_camrip=' + encodeURIComponent(voice.camrip || '0');
            body += '&is_ads=' + encodeURIComponent(voice.ads || '0');
            body += '&is_director=' + encodeURIComponent(voice.director || '0');
            body += '&favs=' + encodeURIComponent(state.page.favs);
            body += '&action=get_movie';
        }

        post(host() + '/ajax/get_cdn_series/?t=' + Date.now(), body, function (json) {
            var qualities = qualityList(json);
            var premium = !!(json && json.premium_content);
            var previous = '';
            qualities.forEach(function (item) {
                if (item.label !== '1080p Ultra') {
                    if (previous && previous !== item.url) premium = false;
                    previous = item.url;
                }
            });
            if (premium) {
                notify('Этот перевод доступен только с HDRezka Premium');
                return;
            }
            if (!qualities.length) {
                notify('HDRezka не вернула доступные ссылки на видео');
                return;
            }
            done(qualities, json);
        }, function () {
            notify('Не удалось получить видеопоток HDRezka');
        });
    }

    function select(items, title, onSelect, onBack) {
        L.Select.show({
            title: title,
            items: items.map(function (item) {
                return {title: item.title || item.label || item.name, subtitle: item.subtitle || ''};
            }),
            onSelect: function (item) {
                var index = items.findIndex(function (x) {
                    return (x.title || x.label || x.name) === item.title;
                });
                onSelect(items[Math.max(0, index)]);
            },
            onBack: onBack || function () {}
        });
    }

    function launchExternalPlayer(url, card, episode) {
        var title = movieTitle(card);
        if (episode && episode.name) title += ' · ' + episode.name;

        // Не подменяем VMP на другой плеер и не вызываем неподтверждённый package/intent.
        // До выяснения API VMP оставляем штатный механизм внешнего плеера Lampa.
        if (L.Android && typeof L.Android.openPlayer === 'function') {
            L.Android.openPlayer(url, {
                title: title,
                url: url,
                media: card && card.name ? 'tv' : 'movie',
                card: card,
                episode: episode || null
            });
        } else {
            notify('В этой сборке нет Android-моста для запуска внешнего плеера.');
        }
    }

    function startFlow(card, page) {
        if (!page.filmId || !page.voices.length) {
            notify('Не удалось распознать страницу HDRezka');
            return;
        }

        var state = {card: card, page: page, quality: null, voice: null, episodes: null, season: null};

        function showQuality() {
            var defaultVoice = page.voices[0];
            var firstEpisode = page.isSeries ? {
                seasonId: page.defaultSeason || (page.seasons[0] && page.seasons[0].id),
                episodeId: page.defaultEpisode || (page.episodes[0] && page.episodes[0].episodeId)
            } : null;

            if (page.isSeries && (!firstEpisode.seasonId || !firstEpisode.episodeId)) {
                fetchEpisodes(state, defaultVoice, function (episodes) {
                    var ep = episodes.episodes[0];
                    if (!ep) return notify('Для этого сериала не найдены серии');
                    fetchStream(state, defaultVoice, ep, showQualityWith);
                });
            } else {
                fetchStream(state, defaultVoice, firstEpisode, showQualityWith);
            }
        }

        function showQualityWith(qualities) {
            var items = qualities.map(function (q, i) {
                return {title: q.label, url: q.url, subtitle: i === 0 ? 'Максимальное доступное качество' : ''};
            });
            select(items, 'Выбор качества', function (chosen) {
                state.quality = chosen;
                showVoices();
            }, function () {
                // Назад к карточке
            });
        }

        function showVoices() {
            var items = page.voices.map(function (voice) {
                return {title: voice.name, voice: voice};
            });
            select(items, 'Выбор озвучки', function (chosen) {
                state.voice = chosen.voice;
                if (page.isSeries) {
                    fetchEpisodes(state, state.voice, function (episodes) {
                        state.episodes = episodes;
                        if (!episodes.seasons.length) {
                            var unique = {};
                            episodes.episodes.forEach(function (ep) {
                                if (ep.seasonId && !unique[ep.seasonId]) {
                                    unique[ep.seasonId] = {id: ep.seasonId, name: 'Сезон ' + ep.seasonId};
                                }
                            });
                            episodes.seasons = Object.keys(unique).map(function (key) { return unique[key]; });
                        }
                        showSeasons();
                    });
                } else {
                    fetchStream(state, state.voice, null, function (qualities) {
                        playWithQuality(qualities, null);
                    });
                }
            }, showQuality);
        }

        function showSeasons() {
            var seasons = state.episodes.seasons || [];
            if (!seasons.length) return notify('Сезоны HDRezka не найдены');
            select(seasons.map(function (s) { return {title: s.name, season: s}; }), 'Выбор сезона', function (chosen) {
                state.season = chosen.season;
                showEpisodes();
            }, showVoices);
        }

        function showEpisodes() {
            var episodes = (state.episodes.episodes || []).filter(function (ep) {
                return String(ep.seasonId) === String(state.season.id);
            });
            if (!episodes.length) return notify('В выбранном сезоне нет доступных серий');
            select(episodes.map(function (ep) { return {title: ep.name, episode: ep}; }), 'Выбор серии', function (chosen) {
                fetchStream(state, state.voice, chosen.episode, function (qualities) {
                    playWithQuality(qualities, chosen.episode);
                });
            }, showSeasons);
        }

        function playWithQuality(qualities, episode) {
            var selected = qualities.find(function (q) {
                return q.label === state.quality.title;
            });
            if (!selected) selected = qualities[0];
            launchExternalPlayer(selected.url, card, episode);
        }

        showQuality();
    }

    function findAndLoad(card) {
        var title = movieTitle(card);
        if (!title) return notify('У карточки нет названия для поиска на HDRezka');

        ensureAuthorization(function () {
            var body = 'q=' + encodeURIComponent(title);
            if (!REQ) REQ = new L.Reguest();
            REQ.clear();
            REQ.timeout(15000);
            REQ.native(proxiedSiteUrl(host() + '/engine/ajax/search.php'), function (html) {
                var matches = parseSearch(html, card);
                if (!matches.length) return notify('На HDRezka ничего не найдено: ' + title);
                var strong = matches.filter(function (item) { return item.score >= 100; });
                var candidates = strong.length ? strong : matches.slice(0, 8);
                select(candidates.map(function (item) {
                    return {title: item.title + (item.year ? ' (' + item.year + ')' : ''), href: item.href};
                }), 'Найдено на HDRezka', function (chosen) {
                    REQ.clear();
                    REQ.timeout(15000);
                    REQ.native(proxiedSiteUrl(chosen.href), function (htmlPage) {
                        var page = parsePage(htmlPage);
                        if (page.filmId) startFlow(card, page);
                        else notify('Не удалось получить данные фильма со страницы HDRezka');
                    }, function (a, c) {
                        notify(REQ.errorDecode ? REQ.errorDecode(a, c) : 'Не удалось открыть страницу HDRezka');
                    }, false, {dataType: 'text', withCredentials: false, headers: headers()});
                }, function () {});
            }, function (a, c) {
                notify(REQ.errorDecode ? REQ.errorDecode(a, c) : 'Поиск HDRezka завершился ошибкой');
            }, body, {dataType: 'text', withCredentials: false, headers: headers()});
        });
    }

    var AUTH_SETTINGS_REGISTERED = false;

    function registerAuthSettings() {
        if (!L || !L.SettingsApi) return false;
        if (AUTH_SETTINGS_REGISTERED) return true;

        var api = L.SettingsApi;
        if (!api.getComponent('hdrezka_auth')) {
            api.addComponent({
                component: 'hdrezka_auth',
                name: 'HDRezka',
                icon: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M4 4h16v3H4zm0 6h16v3H4zm0 6h10v3H4z"/></svg>'
            });
        }

        var existing = api.getParam('hdrezka_auth') || [];
        var names = {};
        existing.forEach(function (item) {
            if (item && item.param && item.param.name) names[item.param.name] = true;
        });

        function add(name, type, label, extra, change, description) {
            if (names[name]) return;
            var param = Object.assign({name: name, type: type}, extra || {});
            // Lampa SettingsApi requires a values entry for every input/select.
            // Without it Params.update() evaluates values[name][key] and crashes.
            if (type === 'input' && typeof param.values === 'undefined') param.values = '';
            api.addParam({
                component: 'hdrezka_auth',
                param: param,
                field: {name: label, description: description || ''},
                onRender: type === 'input' ? function (item) { item.data('string', true); } : undefined,
                onChange: change
            });
            names[name] = true;
        }

        add('hdrezka_auth_account_title', 'title', 'Учётная запись HDRezka');
        add('hdrezka_auth_mirror', 'input', 'Адрес зеркала', {placeholder: 'https://rezka.ag', values: '', default: ''}, function () {
            HOST = '';
            L.Storage.set('hdrezka_auth_cookie', '');
            L.Storage.set('hdrezka_auth_status', 'false');
        }, 'Укажи полный адрес сайта, например https://rezka.ag');
        add('hdrezka_auth_login', 'input', 'Логин или e-mail', {placeholder: 'Логин HDRezka', default: ''});
        add('hdrezka_auth_password', 'input', 'Пароль', {placeholder: 'Пароль HDRezka', default: ''});
        add('hdrezka_auth_login_action', 'button', 'Войти / проверить авторизацию', {}, function () {
            var login = String(storage('hdrezka_auth_login', '') || '').trim();
            var password = String(storage('hdrezka_auth_password', '') || '');
            if (!login || !password) {
                notify('Сначала заполни логин и пароль HDRezka.');
                return;
            }
            notify('Выполняю вход в HDRezka…');
            ensureAuthorization(function () {
                L.Storage.set('hdrezka_auth_status', 'true');
                notify('Авторизация HDRezka подтверждена.');
            });
        }, 'Вход выполняется непосредственно в HDRezka. Данные сохраняются отдельно в этом расширении.');
        add('hdrezka_auth_status_info', 'static', 'Данные авторизации сохраняются отдельно в расширении HDRezka.');
        add('hdrezka_auth_logout_action', 'button', 'Выйти и очистить сессию', {}, function () {
            L.Storage.set('hdrezka_auth_cookie', '');
            L.Storage.set('hdrezka_auth_status', 'false');
            SESSION_COOKIE = '';
            notify('Сессия HDRezka очищена.');
        });
        add('hdrezka_auth_proxy_title', 'title', 'Подключение');
        add('hdrezka_auth_use_proxy', 'trigger', 'Использовать прокси для HDRezka', {default: false});
        add('hdrezka_auth_custom_proxy', 'trigger', 'Использовать собственный прокси', {default: false});
        add('hdrezka_auth_proxy_url', 'input', 'Адрес прокси', {placeholder: 'https://адрес-прокси/', default: ''}, null, 'Необязательно. Нужен, если прямое подключение к зеркалу не работает.');

        AUTH_SETTINGS_REGISTERED = true;
        return true;
    }

    function registerAuthSettingsWhenReady(attempt) {
        if (registerAuthSettings()) return;
        if (attempt < 20) setTimeout(function () {
            registerAuthSettingsWhenReady(attempt + 1);
        }, 250);
    }

    function init() {
        if (!L || !L.Listener || !L.Select || !L.Reguest) return;
        registerAuthSettingsWhenReady(0);
        if (L.Settings && L.Settings.listener && L.Settings.listener.follow) {
            L.Settings.listener.follow('open', function () { registerAuthSettingsWhenReady(0); });
        }
        L.Listener.follow('full', function (e) {
            if (e.type !== 'complite' || !e.data || !e.data.movie || !e.object || !e.object.activity) return;
            var container = e.object.activity.render().find('.full-start-new__buttons');
            if (!container.length || container.find('.view--hdrezka').length) return;

            var button = $(
                '<div class="full-start__button selector view--hdrezka">' +
                    '<svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">' +
                        '<path fill="currentColor" d="M8 5v14l11-7z"></path>' +
                    '</svg><span>HDRezka</span></div>'
            );
            button.on('hover:enter', function () {
                findAndLoad(e.data.movie);
            });
            container.append(button);
        });
    }

    if (window.appready) init();
    else L.Listener.follow('app', function (e) {
        if (e.type === 'ready') init();
    });
})();
