//! Preloaded camouflage site for HTTP traffic that does not qualify as XHTTP.

use crate::config::{FallbackConfig, FallbackMode, SiteConfig};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const CACHE_HTML: &str = "public, max-age=300";
const CACHE_ASSET: &str = "public, max-age=86400, immutable";

#[derive(Clone)]
pub struct StaticReply {
    pub status: StatusCode,
    pub content_type: HeaderValue,
    pub body: Bytes,
    pub cache_control: HeaderValue,
    pub etag: HeaderValue,
    pub last_modified: HeaderValue,
    pub allow: Option<HeaderValue>,
}

#[derive(Clone)]
struct Asset {
    content_type: HeaderValue,
    body: Bytes,
    cache_control: HeaderValue,
    etag: HeaderValue,
    last_modified: HeaderValue,
}

impl Asset {
    fn reply(&self, status: StatusCode) -> StaticReply {
        StaticReply {
            status,
            content_type: self.content_type.clone(),
            body: self.body.clone(),
            cache_control: self.cache_control.clone(),
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
            allow: None,
        }
    }
}

/// Immutable, memory-resident site. Request handling performs no filesystem I/O.
pub struct StaticSite {
    assets: HashMap<String, Asset>,
    not_found: Asset,
    method_not_allowed: Asset,
}

impl StaticSite {
    pub fn from_config(config: &FallbackConfig) -> Result<Self, SiteError> {
        match config.mode {
            FallbackMode::Builtin => Ok(Self::generated(&config.site)),
            FallbackMode::Directory => Self::from_directory(config),
        }
    }

    pub fn resolve(&self, method: &Method, path: &str) -> StaticReply {
        if method != Method::GET && method != Method::HEAD {
            let mut reply = self
                .method_not_allowed
                .reply(StatusCode::METHOD_NOT_ALLOWED);
            reply.allow = Some(HeaderValue::from_static("GET, HEAD"));
            return reply;
        }

        self.assets
            .get(path)
            .map(|asset| asset.reply(StatusCode::OK))
            .unwrap_or_else(|| self.not_found.reply(StatusCode::NOT_FOUND))
    }

    #[cfg(test)]
    fn asset_count(&self) -> usize {
        self.assets.len()
    }

    fn from_directory(config: &FallbackConfig) -> Result<Self, SiteError> {
        let root = config
            .dist
            .as_ref()
            .ok_or(SiteError::MissingDirectory)?
            .canonicalize()
            .map_err(|source| SiteError::Read {
                path: config.dist.clone().unwrap_or_default(),
                source,
            })?;
        if !root.is_dir() {
            return Err(SiteError::NotDirectory(root));
        }

        let mut files = Vec::new();
        collect_files(&root, &root, &mut files)?;
        if files.is_empty() {
            return Err(SiteError::Empty(root));
        }
        files.sort();

        let mut assets = HashMap::with_capacity(files.len().saturating_mul(2));
        let mut total = 0usize;
        for file in files {
            let metadata = fs::metadata(&file).map_err(|source| SiteError::Read {
                path: file.clone(),
                source,
            })?;
            let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if length > config.max_file_bytes {
                return Err(SiteError::FileTooLarge {
                    path: file,
                    length,
                    limit: config.max_file_bytes,
                });
            }
            total = total.checked_add(length).ok_or(SiteError::SiteTooLarge {
                length: usize::MAX,
                limit: config.max_total_bytes,
            })?;
            if total > config.max_total_bytes {
                return Err(SiteError::SiteTooLarge {
                    length: total,
                    limit: config.max_total_bytes,
                });
            }
            let body = fs::read(&file).map_err(|source| SiteError::Read {
                path: file.clone(),
                source,
            })?;
            let relative = file.strip_prefix(&root).expect("collected below root");
            let url = url_path(relative)?;
            let asset = asset(
                &url,
                Bytes::from(body),
                metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            );
            assets.insert(url.clone(), asset.clone());
            if relative
                .file_name()
                .is_some_and(|name| name == config.index.as_str())
            {
                let parent = relative.parent().unwrap_or_else(|| Path::new(""));
                let mut alias = url_path(parent)?;
                if alias != "/" {
                    alias.push('/');
                }
                assets.insert(alias, asset);
            }
        }

        if !assets.contains_key("/") {
            return Err(SiteError::MissingIndex(config.index.clone()));
        }

        let not_found = match config.not_found.as_deref() {
            Some(path) => {
                let key = if path.starts_with('/') {
                    path.to_owned()
                } else {
                    format!("/{path}")
                };
                assets
                    .get(&key)
                    .cloned()
                    .ok_or(SiteError::MissingNotFound(key))?
            }
            None => text_asset(
                "text/html; charset=utf-8",
                default_not_found("Page not found", "Return to the home page"),
                CACHE_HTML,
            ),
        };
        let method_not_allowed = text_asset(
            "text/html; charset=utf-8",
            default_not_found(
                "Method not allowed",
                "This site accepts GET and HEAD requests",
            ),
            "no-store",
        );

        Ok(Self {
            assets,
            not_found,
            method_not_allowed,
        })
    }

    fn generated(config: &SiteConfig) -> Self {
        let generated = GeneratedSite::new(config);
        let mut assets = HashMap::new();
        let home = text_asset("text/html; charset=utf-8", generated.home(), CACHE_HTML);
        assets.insert("/".into(), home.clone());
        assets.insert("/index.html".into(), home);
        assets.insert(
            "/about/".into(),
            text_asset("text/html; charset=utf-8", generated.about(), CACHE_HTML),
        );
        assets.insert(
            "/about".into(),
            assets.get("/about/").expect("inserted").clone(),
        );
        for (slug, page) in generated.posts() {
            let key = format!("/posts/{slug}/");
            let asset = text_asset("text/html; charset=utf-8", page, CACHE_HTML);
            assets.insert(key.trim_end_matches('/').into(), asset.clone());
            assets.insert(key, asset);
        }
        assets.insert(
            "/assets/site.css".into(),
            text_asset("text/css; charset=utf-8", generated.css(), CACHE_ASSET),
        );
        assets.insert(
            "/favicon.svg".into(),
            text_asset("image/svg+xml", generated.favicon(), CACHE_ASSET),
        );
        assets.insert(
            "/favicon.ico".into(),
            assets.get("/favicon.svg").expect("inserted").clone(),
        );
        assets.insert(
            "/robots.txt".into(),
            text_asset(
                "text/plain; charset=utf-8",
                "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n".into(),
                CACHE_HTML,
            ),
        );
        assets.insert(
            "/sitemap.xml".into(),
            text_asset(
                "application/xml; charset=utf-8",
                generated.sitemap(),
                CACHE_HTML,
            ),
        );
        let not_found = text_asset(
            "text/html; charset=utf-8",
            generated.not_found(),
            CACHE_HTML,
        );
        let method_not_allowed = text_asset(
            "text/html; charset=utf-8",
            default_not_found(generated.method_title(), generated.method_description()),
            "no-store",
        );
        Self {
            assets,
            not_found,
            method_not_allowed,
        }
    }
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), SiteError> {
    for entry in fs::read_dir(directory).map_err(|source| SiteError::Read {
        path: directory.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| SiteError::Read {
            path: directory.to_owned(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| SiteError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SiteError::Symlink(path));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            if !path.starts_with(root) {
                return Err(SiteError::EscapesRoot(path));
            }
            files.push(path);
        }
    }
    Ok(())
}

fn url_path(relative: &Path) -> Result<String, SiteError> {
    let mut output = String::from("/");
    let mut first = true;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(SiteError::InvalidPath(relative.to_owned()));
        };
        if !first {
            output.push('/');
        }
        first = false;
        percent_encode(component.as_encoded_bytes(), &mut output);
    }
    Ok(output)
}

fn percent_encode(bytes: &[u8], output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
}

fn asset(path: &str, body: Bytes, modified: SystemTime) -> Asset {
    let content_type = content_type(path);
    let cache_control = if content_type.starts_with("text/html") {
        CACHE_HTML
    } else {
        CACHE_ASSET
    };
    build_asset(content_type, body, cache_control, modified)
}

fn text_asset(content_type: &'static str, body: String, cache_control: &'static str) -> Asset {
    build_asset(
        content_type,
        Bytes::from(body),
        cache_control,
        SystemTime::UNIX_EPOCH,
    )
}

fn build_asset(
    content_type: &'static str,
    body: Bytes,
    cache_control: &'static str,
    modified: SystemTime,
) -> Asset {
    let digest = blake3::hash(&body);
    let etag = format!("\"{}\"", &digest.to_hex()[..24]);
    Asset {
        content_type: HeaderValue::from_static(content_type),
        body,
        cache_control: HeaderValue::from_static(cache_control),
        etag: HeaderValue::from_str(&etag).expect("hex ETag is valid"),
        last_modified: HeaderValue::from_str(&httpdate::fmt_http_date(modified))
            .expect("HTTP date is valid"),
    }
}

fn content_type(path: &str) -> &'static str {
    match path
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

struct GeneratedSite {
    title: String,
    author: String,
    description: String,
    language: &'static str,
    accent: &'static str,
    accent_dark: &'static str,
}

impl GeneratedSite {
    fn new(config: &SiteConfig) -> Self {
        let digest = blake3::hash(config.seed.as_bytes());
        let variant = usize::from(digest.as_bytes()[0]) % 3;
        let chinese = config.language.eq_ignore_ascii_case("zh-cn")
            || config.language.eq_ignore_ascii_case("zh");
        let defaults_en = [
            (
                "Juniper & Stone",
                "Mara Ellison",
                "Notes on slow travel, useful objects, and places worth remembering.",
            ),
            (
                "Common Hours",
                "Theo Arden",
                "A quiet journal about food, craft, books, and everyday city life.",
            ),
            (
                "The Open Window",
                "Noa Linden",
                "Field notes from gardens, coastal walks, and independent studios.",
            ),
        ];
        let defaults_zh = [
            (
                "松石手记",
                "林砚",
                "关于缓慢旅行、日常器物与值得记住的地方。",
            ),
            (
                "寻常时刻",
                "周禾",
                "记录食物、手作、书籍与城市日常的安静刊物。",
            ),
            ("窗外来信", "许岚", "来自花园、海岸步道与独立工作室的随笔。"),
        ];
        let selected = if chinese {
            defaults_zh[variant]
        } else {
            defaults_en[variant]
        };
        let accents = [
            ("#b4553d", "#763425"),
            ("#326a5c", "#20483e"),
            ("#365f8d", "#233f61"),
        ];
        Self {
            title: html_escape(if config.title.is_empty() {
                selected.0
            } else {
                &config.title
            }),
            author: html_escape(if config.author.is_empty() {
                selected.1
            } else {
                &config.author
            }),
            description: html_escape(if config.description.is_empty() {
                selected.2
            } else {
                &config.description
            }),
            language: if chinese { "zh-CN" } else { "en" },
            accent: accents[variant].0,
            accent_dark: accents[variant].1,
        }
    }

    fn home(&self) -> String {
        let (eyebrow, heading, recent, about, post_titles, excerpts) = if self.language == "zh-CN" {
            (
                "独立刊物",
                "给日常留一点从容的空白。",
                "近期文章",
                "关于",
                [
                    "清晨市场里的四种颜色",
                    "沿着旧铁路向海边走",
                    "一张经得起时间的木桌",
                ],
                [
                    "从蔬果摊、旧招牌和夏日光线里，重新发现熟悉街区的色彩。",
                    "一条不再通车的支线，如何变成连接树林与潮汐的安静步道。",
                    "拜访一间小型木工坊，聊聊材料、修补与耐心。",
                ],
            )
        } else {
            (
                "Independent journal",
                "Making room for a slower kind of attention.",
                "Recent stories",
                "About",
                [
                    "Four colors from the morning market",
                    "Walking the old railway to the sea",
                    "A table made to outlast a decade",
                ],
                [
                    "Finding a familiar neighborhood again through produce stalls, old signs, and summer light.",
                    "How a disused branch line became a quiet path between woodland and the tide.",
                    "A visit to a small workshop to talk about material, repair, and patience.",
                ],
            )
        };
        let slugs = [
            "morning-market-colors",
            "railway-to-the-sea",
            "a-lasting-table",
        ];
        let dates = ["August 8, 2026", "July 24, 2026", "July 6, 2026"];
        let mut cards = String::new();
        for index in 0..3 {
            cards.push_str(&format!(
                "<article><p class=\"date\">{}</p><h2><a href=\"/posts/{}/\">{}</a></h2><p>{}</p></article>",
                dates[index], slugs[index], post_titles[index], excerpts[index]
            ));
        }
        format!(
            "<!doctype html><html lang=\"{}\"><head>{}<title>{}</title><meta name=\"description\" content=\"{}\"></head><body><header><a class=\"brand\" href=\"/\">{}</a><nav><a href=\"/about/\">{}</a></nav></header><main><section class=\"hero\"><p class=\"eyebrow\">{}</p><h1>{}</h1><p>{}</p></section><section class=\"posts\"><h2 class=\"section-title\">{}</h2>{}</section></main><footer><p>© 2026 {} · {}</p></footer></body></html>",
            self.language,
            self.head(),
            self.title,
            self.description,
            self.title,
            about,
            eyebrow,
            heading,
            self.description,
            recent,
            cards,
            self.author,
            self.title
        )
    }

    fn about(&self) -> String {
        let (label, heading, paragraph, back) = if self.language == "zh-CN" {
            (
                "关于",
                format!("你好，我是{}。", self.author),
                format!(
                    "{} 是一份由我独立编辑的网络刊物。这里收集旅行途中遇见的人、好用很久的物件，以及值得慢慢观察的普通日子。",
                    self.title
                ),
                "返回首页",
            )
        } else {
            (
                "About",
                format!("Hello, I’m {}.", self.author),
                format!(
                    "{} is an independently edited journal about people met while traveling, objects that age well, and ordinary days worth observing closely.",
                    self.title
                ),
                "Back to the journal",
            )
        };
        self.page(&format!("{} — {}", label, self.title), &format!("<p class=\"eyebrow\">{label}</p><h1>{heading}</h1><p>{paragraph}</p><p><a href=\"/\">{back}</a></p>"))
    }

    fn posts(&self) -> [(&'static str, String); 3] {
        let english = [
            (
                "Four colors from the morning market",
                "August 8, 2026",
                "The market changes character before the rest of the street wakes. Apricot, deep green, chalk white, and the red of hand-painted signs repeat from stall to stall. None of it was arranged as a palette, which is exactly why it works.",
                "Looking closely",
                "A camera helps, but a small notebook is better. Writing down one precise color or texture slows the eye enough to notice how much design already exists in ordinary places.",
            ),
            (
                "Walking the old railway to the sea",
                "July 24, 2026",
                "The rails disappeared years ago, but the route remains legible in gentle curves and stone bridges. Ferns have taken the shaded cuttings, while the open stretches carry the smell of salt long before the water appears.",
                "A path with memory",
                "Good routes keep traces of their former purpose. The old platforms now hold benches, and station names survive on weathered tiles beside bicycle maps.",
            ),
            (
                "A table made to outlast a decade",
                "July 6, 2026",
                "The workshop keeps every offcut large enough to become a handle, wedge, or repair. Nothing feels precious, but everything is considered. The resulting table is simple because the difficult decisions happened before assembly.",
                "Designed for repair",
                "The maker leaves joints visible and finishes the surface with oil. Scratches can be sanded, loose parts tightened, and the color will deepen instead of peeling away.",
            ),
        ];
        let chinese = [
            (
                "清晨市场里的四种颜色",
                "2026 年 8 月 8 日",
                "整条街还没醒来时，市场已经有了自己的节奏。杏黄、深绿、粉笔白，还有手绘招牌的红，在不同摊位之间反复出现。它们并非刻意搭配，却因此格外自然。",
                "认真看一会儿",
                "相机当然有用，但小笔记本更能让目光慢下来。写下一种准确的颜色或触感，便会发现普通地方原本就藏着许多设计。",
            ),
            (
                "沿着旧铁路向海边走",
                "2026 年 7 月 24 日",
                "铁轨早已拆除，缓慢的弯道和石桥仍然清楚地标记着路线。蕨类占据了背阴的路堑，开阔处则在见到海水之前很久便带来了盐的气味。",
                "一条有记忆的路",
                "好的步道会保留过去用途的痕迹。旧站台放上了长椅，风化的站名瓷砖旁则出现了自行车地图。",
            ),
            (
                "一张经得起时间的木桌",
                "2026 年 7 月 6 日",
                "工坊留下每一块足以做成把手、木楔或补丁的边角料。没有什么被过分珍藏，但每件事都经过考虑。桌子最终显得简单，是因为困难的决定都发生在组装以前。",
                "为修补而设计",
                "制作者让接缝保持可见，只用木油处理表面。划痕可以磨平，松动处能够拧紧，颜色也会逐年变深，而不是成片剥落。",
            ),
        ];
        let selected = if self.language == "zh-CN" {
            chinese
        } else {
            english
        };
        let slugs = [
            "morning-market-colors",
            "railway-to-the-sea",
            "a-lasting-table",
        ];
        std::array::from_fn(|index| {
            let post = selected[index];
            (
                slugs[index],
                self.page(
                    &format!("{} — {}", post.0, self.title),
                    &format!(
                        "<p class=\"date\">{}</p><h1>{}</h1><p>{}</p><h2>{}</h2><p>{}</p>",
                        post.1, post.0, post.2, post.3, post.4
                    ),
                ),
            )
        })
    }

    fn page(&self, title: &str, content: &str) -> String {
        format!(
            "<!doctype html><html lang=\"{}\"><head>{}<title>{}</title></head><body><header><a class=\"brand\" href=\"/\">{}</a></header><main class=\"article\">{}</main><footer><p>© 2026 {} · {}</p></footer></body></html>",
            self.language,
            self.head(),
            title,
            self.title,
            content,
            self.author,
            self.title
        )
    }

    fn head(&self) -> String {
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><link rel=\"icon\" href=\"/favicon.svg\" type=\"image/svg+xml\"><link rel=\"stylesheet\" href=\"/assets/site.css\">".into()
    }

    fn css(&self) -> String {
        format!(
            ":root{{--accent:{};--accent-dark:{};--paper:#f7f3eb;--ink:#20211f;--muted:#6d6d65}}*{{box-sizing:border-box}}html{{font-family:Georgia,'Noto Serif SC',serif;color:var(--ink);background:var(--paper)}}body{{margin:0}}header,main,footer{{max-width:940px;margin:auto;padding-left:24px;padding-right:24px}}header{{padding-top:32px;padding-bottom:28px;display:flex;justify-content:space-between;border-bottom:1px solid #d9d3c7}}.brand{{font-family:ui-sans-serif,system-ui,sans-serif;font-weight:750;letter-spacing:.04em;color:var(--ink)}}nav{{display:flex;gap:20px}}a{{color:var(--accent-dark);text-decoration:none}}a:hover{{text-decoration:underline}}.hero{{max-width:780px;padding:88px 0 70px}}.eyebrow,.date,.section-title{{font:700 12px/1.3 ui-sans-serif,system-ui,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}}h1{{font-size:clamp(42px,7vw,72px);line-height:1.03;letter-spacing:-.035em;margin:12px 0 24px}}.hero>p:last-child,.article p{{font-size:19px;line-height:1.75;color:#4a4b46}}.posts{{padding:0 0 80px}}.posts article{{display:grid;grid-template-columns:145px 1fr;gap:18px;border-top:1px solid #d9d3c7;padding:30px 0}}.posts article h2{{font-size:26px;margin:0 0 10px}}.posts article p{{line-height:1.65;margin:0;color:var(--muted)}}.posts .date{{grid-row:1/3}}.article{{max-width:760px;padding-top:70px;padding-bottom:90px}}.article h1{{font-size:clamp(38px,6vw,62px)}}.article h2{{font-size:26px;margin-top:42px}}footer{{padding-top:28px;padding-bottom:42px;border-top:1px solid #d9d3c7;color:var(--muted);font:14px ui-sans-serif,system-ui,sans-serif}}@media(max-width:650px){{.hero{{padding:62px 0 48px}}.posts article{{grid-template-columns:1fr}}.posts .date{{grid-row:auto}}}}",
            self.accent, self.accent_dark
        )
    }

    fn favicon(&self) -> String {
        let letter = self.title.chars().next().unwrap_or('J');
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\"><rect width=\"64\" height=\"64\" rx=\"15\" fill=\"{}\"/><text x=\"32\" y=\"43\" text-anchor=\"middle\" font-family=\"Georgia,serif\" font-size=\"36\" fill=\"#fff\">{}</text></svg>",
            self.accent, letter
        )
    }

    fn sitemap(&self) -> String {
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>/</loc></url><url><loc>/about/</loc></url><url><loc>/posts/morning-market-colors/</loc></url><url><loc>/posts/railway-to-the-sea/</loc></url><url><loc>/posts/a-lasting-table/</loc></url></urlset>".into()
    }

    fn not_found(&self) -> String {
        let (title, description) = if self.language == "zh-CN" {
            (
                "没有找到页面",
                "这篇内容可能已经移动。返回首页查看近期文章。",
            )
        } else {
            (
                "Page not found",
                "This story may have moved. Return home for the latest entries.",
            )
        };
        self.page(title, &format!("<p class=\"eyebrow\">404</p><h1>{title}</h1><p>{description}</p><p><a href=\"/\">Home</a></p>"))
    }

    fn method_title(&self) -> &'static str {
        if self.language == "zh-CN" {
            "不支持此请求方式"
        } else {
            "Method not allowed"
        }
    }

    fn method_description(&self) -> &'static str {
        if self.language == "zh-CN" {
            "此网站仅接受 GET 与 HEAD 请求"
        } else {
            "This site accepts GET and HEAD requests"
        }
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn default_not_found(title: &str, description: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head><body><main><h1>{title}</h1><p>{description}</p><p><a href=\"/\">Home</a></p></main></body></html>"
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("fallback directory is missing")]
    MissingDirectory,
    #[error("fallback path is not a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("fallback directory is empty: {0}")]
    Empty(PathBuf),
    #[error("failed to read fallback path {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("symlinks are not allowed in fallback directory: {0}")]
    Symlink(PathBuf),
    #[error("fallback path escapes configured root: {0}")]
    EscapesRoot(PathBuf),
    #[error("invalid fallback path: {0}")]
    InvalidPath(PathBuf),
    #[error("fallback file {path} is {length} bytes; limit is {limit}")]
    FileTooLarge {
        path: PathBuf,
        length: usize,
        limit: usize,
    },
    #[error("fallback site is {length} bytes; limit is {limit}")]
    SiteTooLarge { length: usize, limit: usize },
    #[error("fallback directory has no configured index file {0}")]
    MissingIndex(String),
    #[error("configured fallback.notFound asset does not exist: {0}")]
    MissingNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn generated_site_is_seeded_and_customizable() {
        let config = SiteConfig {
            seed: "example.com".into(),
            title: "Aster Journal".into(),
            author: "Mei".into(),
            description: "Small observations".into(),
            language: "en".into(),
        };
        let site = StaticSite::generated(&config);
        let index = site.resolve(&Method::GET, "/");
        assert_eq!(index.status, StatusCode::OK);
        assert!(index.body.windows(13).any(|w| w == b"Aster Journal"));
        assert!(site.asset_count() >= 10);
        assert_eq!(
            site.resolve(&Method::GET, "/missing").status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn directory_site_is_preloaded_with_index_alias() {
        let root = tempfile_dir();
        fs::write(root.join("index.html"), b"<h1>custom</h1>").unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/app.css"), b"body{}").unwrap();
        let config = FallbackConfig {
            mode: FallbackMode::Directory,
            dist: Some(root.clone()),
            ..FallbackConfig::default()
        };
        let site = StaticSite::from_config(&config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(site.resolve(&Method::GET, "/").body, "<h1>custom</h1>");
        assert_eq!(
            site.resolve(&Method::GET, "/assets/app.css").content_type,
            "text/css; charset=utf-8"
        );
    }

    #[test]
    fn directory_site_rejects_oversized_file() {
        let root = tempfile_dir();
        fs::write(root.join("index.html"), b"too large").unwrap();
        let config = FallbackConfig {
            mode: FallbackMode::Directory,
            dist: Some(root.clone()),
            max_file_bytes: 2,
            max_total_bytes: 2,
            ..FallbackConfig::default()
        };
        assert!(matches!(
            StaticSite::from_config(&config),
            Err(SiteError::FileTooLarge { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn directory_site_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let root = tempfile_dir();
        fs::write(root.join("index.html"), b"ok").unwrap();
        symlink("index.html", root.join("alias.html")).unwrap();
        let config = FallbackConfig {
            mode: FallbackMode::Directory,
            dist: Some(root.clone()),
            ..FallbackConfig::default()
        };
        assert!(matches!(
            StaticSite::from_config(&config),
            Err(SiteError::Symlink(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    fn tempfile_dir() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rust-xhttp-site-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        let mut marker = fs::File::create(path.join(".test-marker")).unwrap();
        marker.write_all(b"marker").unwrap();
        fs::remove_file(path.join(".test-marker")).unwrap();
        path
    }
}
