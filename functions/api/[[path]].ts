export interface Env {
  DB: D1Database;
  AI_ENDPOINT?: string;
  AI_MODEL?: string;
}

type PagesFunction<E> = (context: {
  request: Request;
  env: E;
}) => Response | Promise<Response>;
type Db = D1Database;
type User = {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar_seed: string;
  avatar_style: string;
  bio: string;
  status: string;
  last_seen_at: string;
  created_at: string;
  is_online: number;
  privacy_json?: string;
};
type Session = { user: User };
const MAX_MESSAGE = 4000;
// Keep password derivation within Cloudflare's free CPU budget while retaining a salted, server-side PBKDF2 hash.
const PASSWORD_ITERATIONS = 20000;
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
const readJson = async <T>(request: Request) => {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
};
const normalizeUsername = (value: string) =>
  value.trim().replace(/^@/, "").toLowerCase();
const safeUser = (u: User | undefined | null) =>
  u
    ? {
        id: u.id,
        name: u.name,
        username: u.username,
        avatarSeed: u.avatar_seed,
        avatarStyle: u.avatar_style,
        avatarEmoji: (() => {
          try {
            return u.privacy_json
              ? JSON.parse(u.privacy_json).avatarEmoji || ""
              : "";
          } catch {
            return "";
          }
        })(),
        bio: u.bio,
        status: u.status,
        lastSeenAt: u.last_seen_at,
        createdAt: u.created_at,
        isOnline: Boolean(u.is_online),
      }
    : null;
const cookie = (value: string, maxAge: number) =>
  `cg_session=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
async function digest(value: string) {
  const b = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(b)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
async function hashPassword(password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PASSWORD_ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return `pbkdf2$${PASSWORD_ITERATIONS}$${btoa(String.fromCharCode(...salt))}$${btoa(String.fromCharCode(...new Uint8Array(bits)))}`;
}
async function verifyPassword(password: string, stored: string) {
  const [kind, iterations, saltB64, hashB64] = stored.split("$");
  if (kind !== "pbkdf2") return false;
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: Number(iterations), hash: "SHA-256" },
    key,
    256,
  );
  const expected = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return expected === hashB64;
}
function initials(name: string) {
  return (
    name
      .split(/\s+/)
      .slice(0, 2)
      .map((x) => x[0])
      .join("")
      .toUpperCase() || "?"
  );
}
async function session(request: Request, db: Db): Promise<Session | null> {
  const raw = request.headers
    .get("cookie")
    ?.match(/(?:^|; )cg_session=([^;]+)/)?.[1];
  if (!raw) return null;
  const tokenHash = await digest(raw);
  const row = await db
    .prepare(
      `SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`,
    )
    .bind(tokenHash, now())
    .first<User>();
  return row ? { user: row } : null;
}
async function requireSession(request: Request, db: Db) {
  const s = await session(request, db);
  if (!s) throw new HttpError(401, "Требуется вход");
  return s;
}
class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, message: string, code = "BAD_REQUEST") {
    super(message);
    this.status = status;
    this.code = code;
  }
}
function assertString(v: unknown, field: string, max: number) {
  if (typeof v !== "string" || !v.trim() || v.length > max)
    throw new HttpError(400, `Некорректное поле: ${field}`);
  return v.trim();
}
async function createSession(db: Db, userId: string, request: Request) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  const t = now(),
    expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  await db
    .prepare(
      `INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at,user_agent,ip_hash) VALUES(?,?,?,?,?,?,?)`,
    )
    .bind(
      id(),
      userId,
      await digest(token),
      t,
      expires,
      request.headers.get("user-agent") || "",
      await digest(request.headers.get("cf-connecting-ip") || ""),
    )
    .run();
  return token;
}
async function userChat(db: Db, userId: string, chatId: string) {
  return db
    .prepare(
      `SELECT c.*, cm.role, cm.unread_count FROM chats c JOIN chat_members cm ON cm.chat_id=c.id WHERE c.id=? AND cm.user_id=?`,
    )
    .bind(chatId, userId)
    .first<any>();
}
async function chatAllowed(db: Db, userId: string, chatId: string) {
  const chat = await userChat(db, userId, chatId);
  if (!chat) throw new HttpError(404, "Чат не найден");
  return chat;
}
async function groupRole(db: Db, userId: string, chatId: string) {
  return db
    .prepare("SELECT role FROM group_members WHERE chat_id=? AND user_id=?")
    .bind(chatId, userId)
    .first<{ role: string }>();
}
async function requireGroupAdmin(
  db: Db,
  userId: string,
  chatId: string,
  ownerOnly = false,
) {
  await chatAllowed(db, userId, chatId);
  const member = await groupRole(db, userId, chatId);
  if (
    !member ||
    (ownerOnly
      ? member.role !== "owner"
      : !["owner", "admin"].includes(member.role))
  )
    throw new HttpError(
      403,
      "Недостаточно прав для управления группой",
      "FORBIDDEN",
    );
  return member.role;
}
async function rateLimit(
  request: Request,
  key: string,
  max: number,
  windowMs: number,
) {
  const globalThisAny = globalThis as any;
  globalThisAny.__cgRate ??= new Map<
    string,
    { start: number; count: number }
  >();
  const map = globalThisAny.__cgRate as Map<
    string,
    { start: number; count: number }
  >;
  const current = Date.now(),
    prev = map.get(key);
  if (!prev || current - prev.start > windowMs)
    map.set(key, { start: current, count: 1 });
  else {
    prev.count++;
    if (prev.count > max)
      throw new HttpError(429, "Слишком много запросов. Попробуйте позже.");
  }
}

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  try {
    if (!env.DB) return json({ error: "D1 не подключена" }, 503);
    if (request.method === "OPTIONS")
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type",
        },
      });
    if (path === "health")
      return json({ ok: true, service: "cloudgram", time: now() });
    if (path === "auth/register" && request.method === "POST") {
      await rateLimit(
        request,
        "register:" + ((request as any).cf?.country || "global"),
        5,
        60 * 60 * 1000,
      );
      const body = await readJson<{
        name: string;
        username: string;
        email: string;
        password: string;
        passwordConfirm: string;
      }>(request);
      if (!body) throw new HttpError(400, "Некорректное тело запроса");
      const name = assertString(body.name, "name", 80),
        username = normalizeUsername(
          assertString(body.username, "username", 25),
        ),
        email = assertString(body.email, "email", 160).toLowerCase(),
        password = assertString(body.password, "password", 128);
      if (!/^[a-z0-9_]{3,24}$/.test(username))
        throw new HttpError(400, "Username: 3–24 символа, только a-z, 0-9 и _");
      if (!/^\S+@\S+\.\S+$/.test(email))
        throw new HttpError(400, "Введите корректный email");
      if (password.length < 8)
        throw new HttpError(400, "Пароль должен быть не короче 8 символов");
      if (password !== body.passwordConfirm)
        throw new HttpError(400, "Пароли не совпадают");
      if (
        await env.DB.prepare("SELECT id FROM users WHERE username=? OR email=?")
          .bind(username, email)
          .first()
      )
        throw new HttpError(409, "Username или email уже занят", "CONFLICT");
      const uid = id(),
        t = now(),
        hash = await hashPassword(password);
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO users(id,name,username,email,password_hash,avatar_seed,avatar_style,last_seen_at,created_at,status,is_online) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
        ).bind(
          uid,
          name,
          username,
          email,
          hash,
          uid,
          "aurora",
          t,
          t,
          "В сети",
          1,
        ),
        env.DB.prepare(
          `INSERT INTO username_index(username,user_id) VALUES(?,?)`,
        ).bind(username, uid),
        env.DB.prepare(
          `INSERT INTO user_settings(user_id,updated_at) VALUES(?,?)`,
        ).bind(uid, t),
      ]);
      const token = await createSession(env.DB, uid, request);
      return json(
        {
          user: safeUser(
            await env.DB.prepare("SELECT * FROM users WHERE id=?")
              .bind(uid)
              .first<User>(),
          ),
        },
        200,
        { "set-cookie": cookie(token, 60 * 60 * 24 * 30) },
      );
    }
    if (path === "auth/login" && request.method === "POST") {
      await rateLimit(
        request,
        "login:" + ((request as any).cf?.country || "global"),
        20,
        15 * 60 * 1000,
      );
      const body = await readJson<{
        email: string;
        password: string;
        remember?: boolean;
      }>(request);
      if (!body) throw new HttpError(400, "Некорректное тело запроса");
      const email = assertString(body.email, "email", 160).toLowerCase(),
        password = assertString(body.password, "password", 128);
      const u = await env.DB.prepare("SELECT * FROM users WHERE email=?")
        .bind(email)
        .first<any>();
      if (!u || !(await verifyPassword(password, u.password_hash)))
        throw new HttpError(
          401,
          "Неверный email или пароль",
          "INVALID_CREDENTIALS",
        );
      const t = now();
      await env.DB.prepare(
        "UPDATE users SET is_online=1,status=?,last_seen_at=? WHERE id=?",
      )
        .bind("В сети", t, u.id)
        .run();
      const token = await createSession(env.DB, u.id, request);
      return json(
        { user: safeUser({ ...u, last_seen_at: t, is_online: 1 }) },
        200,
        {
          "set-cookie": cookie(
            token,
            body.remember === false ? 60 * 60 * 24 : 60 * 60 * 24 * 30,
          ),
        },
      );
    }
    if (path === "auth/logout" && request.method === "POST") {
      const raw = request.headers
        .get("cookie")
        ?.match(/(?:^|; )cg_session=([^;]+)/)?.[1];
      if (raw) {
        const h = await digest(raw);
        await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?")
          .bind(h)
          .run();
      }
      return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
    }
    if (path === "me" && request.method === "GET") {
      const s = await session(request, env.DB);
      if (!s) return json({ user: null });
      const settings = await env.DB.prepare(
        "SELECT * FROM user_settings WHERE user_id=?",
      )
        .bind(s.user.id)
        .first<any>();
      return json({ user: safeUser(s.user), settings });
    }
    const s = await requireSession(request, env.DB);
    const me = s.user;
    if (path === "users/search" && request.method === "GET") {
      await rateLimit(request, "search:" + me.id, 60, 60 * 1000);
      const q = normalizeUsername(url.searchParams.get("q") || "");
      if (q.length < 2) return json({ users: [] });
      const rows = await env.DB.prepare(
        `SELECT id,name,username,avatar_seed,avatar_style,bio,status,last_seen_at,created_at,is_online FROM users WHERE username LIKE ? COLLATE NOCASE OR name LIKE ? COLLATE NOCASE ORDER BY CASE WHEN username=? THEN 0 ELSE 1 END, username LIMIT 20`,
      )
        .bind(`${q}%`, `%${q}%`, q)
        .all<User>();
      return json({ users: (rows.results || []).map(safeUser) });
    }
    if (path === "profile" && request.method === "PATCH") {
      const body = await readJson<{
        name?: string;
        username?: string;
        bio?: string;
        avatarStyle?: string;
        avatarEmoji?: string;
      }>(request);
      if (!body) throw new HttpError(400, "Некорректное тело");
      const name =
          body.name === undefined
            ? me.name
            : assertString(body.name, "name", 80),
        bio = body.bio === undefined ? me.bio : String(body.bio).slice(0, 280),
        style =
          body.avatarStyle &&
          ["aurora", "sunset", "mint", "mono"].includes(body.avatarStyle)
            ? body.avatarStyle
            : me.avatar_style;
      let username = me.username;
      if (body.username !== undefined) {
        username = normalizeUsername(
          assertString(body.username, "username", 25),
        );
        if (!/^[a-z0-9_]{3,24}$/.test(username))
          throw new HttpError(400, "Некорректный username");
        const taken = await env.DB.prepare(
          "SELECT id FROM users WHERE username=? AND id<>?",
        )
          .bind(username, me.id)
          .first();
        if (taken) throw new HttpError(409, "Username уже занят");
      }
      let avatarEmoji = "";
      try {
        avatarEmoji = String(
          body.avatarEmoji === undefined
            ? JSON.parse(me.privacy_json || "{}").avatarEmoji || ""
            : body.avatarEmoji,
        ).slice(0, 8);
      } catch {
        avatarEmoji = String(body.avatarEmoji || "").slice(0, 8);
      }
      const privacyJson = JSON.stringify({
        avatarEmoji,
      });
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE users SET name=?,username=?,bio=?,avatar_style=?,privacy_json=? WHERE id=?",
        ).bind(name, username, bio, style, privacyJson, me.id),
        env.DB.prepare(
          "UPDATE username_index SET username=? WHERE user_id=?",
        ).bind(username, me.id),
      ]);
      return json({
        user: safeUser(
          await env.DB.prepare("SELECT * FROM users WHERE id=?")
            .bind(me.id)
            .first<User>(),
        ),
      });
    }
    if (path === "settings" && request.method === "PATCH") {
      const body = await readJson<any>(request);
      if (!body) throw new HttpError(400, "Некорректное тело");
      const theme = ["light", "dark", "system"].includes(body.theme)
          ? body.theme
          : "system",
        accent = ["violet", "ocean", "emerald", "midnight"].includes(
          body.accent,
        )
          ? body.accent
          : "violet";
      await env.DB.prepare(
        `INSERT INTO user_settings(user_id,theme,accent,language,notifications,sound,compact_mode,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET theme=excluded.theme,accent=excluded.accent,language=excluded.language,notifications=excluded.notifications,sound=excluded.sound,compact_mode=excluded.compact_mode,updated_at=excluded.updated_at`,
      )
        .bind(
          me.id,
          theme,
          accent,
          body.language || "ru",
          body.notifications === false ? 0 : 1,
          body.sound === false ? 0 : 1,
          body.compactMode ? 1 : 0,
          now(),
        )
        .run();
      return json({
        settings: await env.DB.prepare(
          "SELECT * FROM user_settings WHERE user_id=?",
        )
          .bind(me.id)
          .first(),
      });
    }
    if (path === "chats" && request.method === "GET") {
      const rows = await env.DB.prepare(
        `SELECT c.id,c.kind,c.title,c.owner_id,c.updated_at,c.pinned,c.archived,cm.unread_count,cm.role,(SELECT body FROM messages m WHERE m.id=c.last_message_id) last_body,(SELECT created_at FROM messages m WHERE m.id=c.last_message_id) last_message_at,pu.id peer_id,pu.name peer_name,pu.username peer_username,pu.avatar_seed peer_avatar_seed,pu.avatar_style peer_avatar_style,pu.status peer_status,pu.is_online peer_online FROM chats c JOIN chat_members cm ON cm.chat_id=c.id LEFT JOIN chat_members other ON other.chat_id=c.id AND other.user_id<>? LEFT JOIN users pu ON pu.id=other.user_id WHERE cm.user_id=? ORDER BY c.pinned DESC,c.updated_at DESC LIMIT 100`,
      )
        .bind(me.id, me.id)
        .all<any>();
      return json({ chats: rows.results || [] });
    }
    if (path === "chats/direct" && request.method === "POST") {
      const body = await readJson<{ username: string }>(request);
      const username = normalizeUsername(
        assertString(body?.username, "username", 25),
      );
      const other = await env.DB.prepare("SELECT * FROM users WHERE username=?")
        .bind(username)
        .first<User>();
      if (!other) throw new HttpError(404, "Пользователь не найден");
      if (other.id === me.id)
        throw new HttpError(400, "Нельзя создать чат с собой");
      if (
        await env.DB.prepare(
          "SELECT 1 FROM user_blocks WHERE user_id=? AND blocked_user_id=?",
        )
          .bind(other.id, me.id)
          .first()
      )
        throw new HttpError(403, "Пользователь ограничил входящие сообщения");
      let chat = await env.DB.prepare(
        `SELECT c.id FROM chats c JOIN chat_members a ON a.chat_id=c.id JOIN chat_members b ON b.chat_id=c.id WHERE c.kind='direct' AND a.user_id=? AND b.user_id=?`,
      )
        .bind(me.id, other.id)
        .first<{ id: string }>();
      if (!chat) {
        const cid = id(),
          t = now();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO chats(id,kind,title,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",
          ).bind(cid, "direct", null, me.id, t, t),
          env.DB.prepare(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,?,?)",
          ).bind(cid, me.id, "member", t),
          env.DB.prepare(
            "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,?,?)",
          ).bind(cid, other.id, "member", t),
        ]);
        chat = { id: cid };
      }
      return json({ chatId: chat.id });
    }
    const chatMessage = path.match(/^chats\/([^/]+)\/messages$/);
    if (chatMessage) {
      const chatId = chatMessage[1];
      await chatAllowed(env.DB, me.id, chatId);
      if (request.method === "GET") {
        const limit = Math.min(
            Number(url.searchParams.get("limit") || 40),
            100,
          ),
          before = url.searchParams.get("before");
        const sql = before
          ? `SELECT m.*,u.name sender_name,u.username sender_username,u.avatar_seed sender_avatar_seed,(SELECT json_group_array(json_object('emoji',r.emoji,'count',r.cnt,'mine',r.mine)) FROM (SELECT emoji,COUNT(*) cnt,SUM(user_id=?) mine FROM message_reactions WHERE message_id=m.id GROUP BY emoji) r) reactions FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? AND m.created_at<? ORDER BY m.created_at DESC LIMIT ?`
          : `SELECT m.*,u.name sender_name,u.username sender_username,u.avatar_seed sender_avatar_seed,(SELECT json_group_array(json_object('emoji',r.emoji,'count',r.cnt,'mine',r.mine)) FROM (SELECT emoji,COUNT(*) cnt,SUM(user_id=?) mine FROM message_reactions WHERE message_id=m.id GROUP BY emoji) r) reactions FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? ORDER BY m.created_at DESC LIMIT ?`;
        const args = before
          ? [me.id, chatId, before, limit]
          : [me.id, chatId, limit];
        const rows = await env.DB.prepare(sql)
          .bind(...args)
          .all<any>();
        return json({
          messages: (rows.results || []).reverse().map((x) => ({
            ...x,
            reactions: x.reactions ? JSON.parse(x.reactions) : [],
          })),
        });
      }
      if (request.method === "POST") {
        await rateLimit(request, "message:" + me.id, 90, 60 * 1000);
        const body = await readJson<{
          body: string;
          replyToId?: string;
          forwardedFromId?: string;
        }>(request);
        const text = assertString(body?.body, "body", MAX_MESSAGE);
        if (text.length > MAX_MESSAGE)
          throw new HttpError(400, "Сообщение слишком длинное");
        const chat = await userChat(env.DB, me.id, chatId);
        if (chat.kind === "direct") {
          const other = await env.DB.prepare(
            "SELECT user_id FROM chat_members WHERE chat_id=? AND user_id<>?",
          )
            .bind(chatId, me.id)
            .first<{ user_id: string }>();
          if (
            other &&
            (await env.DB.prepare(
              "SELECT 1 FROM user_blocks WHERE user_id=? AND blocked_user_id=?",
            )
              .bind(other.user_id, me.id)
              .first())
          )
            throw new HttpError(
              403,
              "Вы заблокированы и не можете отправить сообщение",
              "BLOCKED",
            );
        }
        const mid = id(),
          t = now();
        await env.DB.batch([
          env.DB.prepare(
            "INSERT INTO messages(id,chat_id,sender_id,body,reply_to_id,forwarded_from_id,created_at) VALUES(?,?,?,?,?,?,?)",
          ).bind(
            mid,
            chatId,
            me.id,
            text,
            body?.replyToId || null,
            body?.forwardedFromId || null,
            t,
          ),
          env.DB.prepare(
            "UPDATE chats SET updated_at=?,last_message_id=? WHERE id=?",
          ).bind(t, mid, chatId),
          env.DB.prepare(
            "UPDATE chat_members SET unread_count=unread_count+1 WHERE chat_id=? AND user_id<>?",
          ).bind(chatId, me.id),
        ]);
        return json(
          {
            message: {
              id: mid,
              chat_id: chatId,
              sender_id: me.id,
              body: text,
              created_at: t,
              sender_name: me.name,
              sender_username: me.username,
              reactions: [],
            },
          },
          201,
        );
      }
    }
    const messageId = path.match(/^messages\/([^/]+)(?:\/(reaction))?$/);
    if (messageId) {
      const mid = messageId[1];
      const m = await env.DB.prepare("SELECT * FROM messages WHERE id=?")
        .bind(mid)
        .first<any>();
      if (!m) throw new HttpError(404, "Сообщение не найдено");
      await chatAllowed(env.DB, me.id, m.chat_id);
      if (messageId[2] === "reaction" && request.method === "POST") {
        const body = await readJson<{ emoji: string }>(request);
        const emoji = assertString(body?.emoji, "emoji", 8);
        const existing = await env.DB.prepare(
          "SELECT emoji FROM message_reactions WHERE message_id=? AND user_id=?",
        )
          .bind(mid, me.id)
          .first<{ emoji: string }>();
        if (existing?.emoji === emoji)
          await env.DB.prepare(
            "DELETE FROM message_reactions WHERE message_id=? AND user_id=?",
          )
            .bind(mid, me.id)
            .run();
        else
          await env.DB.prepare(
            `INSERT INTO message_reactions(message_id,user_id,emoji,created_at) VALUES(?,?,?,?) ON CONFLICT(message_id,user_id) DO UPDATE SET emoji=excluded.emoji,created_at=excluded.created_at`,
          )
            .bind(mid, me.id, emoji, now())
            .run();
        return json({ ok: true });
      }
      if (request.method === "PATCH") {
        if (m.sender_id !== me.id)
          throw new HttpError(
            403,
            "Можно изменять только свои сообщения",
            "FORBIDDEN",
          );
        const body = await readJson<{ body: string }>(request);
        const text = assertString(body?.body, "body", MAX_MESSAGE);
        await env.DB.prepare(
          "UPDATE messages SET body=?,edited_at=? WHERE id=? AND sender_id=?",
        )
          .bind(text, now(), mid, me.id)
          .run();
        return json({ ok: true });
      }
      if (request.method === "DELETE") {
        if (m.sender_id !== me.id)
          throw new HttpError(
            403,
            "Можно удалить только свои сообщения",
            "FORBIDDEN",
          );
        await env.DB.prepare(
          "UPDATE messages SET body=?,deleted_at=? WHERE id=? AND sender_id=?",
        )
          .bind("", now(), mid, me.id)
          .run();
        return json({ ok: true });
      }
    }
    const read = path.match(/^chats\/([^/]+)\/read$/);
    if (read && request.method === "POST") {
      await chatAllowed(env.DB, me.id, read[1]);
      await env.DB.prepare(
        "UPDATE chat_members SET unread_count=0,last_read_at=? WHERE chat_id=? AND user_id=?",
      )
        .bind(now(), read[1], me.id)
        .run();
      return json({ ok: true });
    }
    if (path === "blocks" && request.method === "POST") {
      const body = await readJson<{ userId: string }>(request);
      if (!body?.userId || body.userId === me.id)
        throw new HttpError(400, "Некорректный пользователь");
      await env.DB.prepare(
        "INSERT OR IGNORE INTO user_blocks(user_id,blocked_user_id,created_at) VALUES(?,?,?)",
      )
        .bind(me.id, body.userId, now())
        .run();
      return json({ ok: true });
    }
    const block = path.match(/^blocks\/([^/]+)$/);
    if (block && request.method === "GET") {
      const blocked = await env.DB.prepare(
        "SELECT 1 FROM user_blocks WHERE user_id=? AND blocked_user_id=?",
      )
        .bind(me.id, block[1])
        .first();
      return json({ blocked: Boolean(blocked) });
    }
    if (block && request.method === "DELETE") {
      await env.DB.prepare(
        "DELETE FROM user_blocks WHERE user_id=? AND blocked_user_id=?",
      )
        .bind(me.id, block[1])
        .run();
      return json({ ok: true });
    }
    if (path === "reports" && request.method === "POST") {
      const body = await readJson<{
        targetUserId?: string;
        messageId?: string;
        reason: string;
        details?: string;
      }>(request);
      const reason = ["spam", "abuse", "harassment", "other"].includes(
        body?.reason || "",
      )
        ? body?.reason
        : "other";
      await env.DB.prepare(
        "INSERT INTO reports(id,reporter_id,target_user_id,message_id,reason,details,created_at) VALUES(?,?,?,?,?,?,?)",
      )
        .bind(
          id(),
          me.id,
          body?.targetUserId || null,
          body?.messageId || null,
          reason,
          body?.details || "",
          now(),
        )
        .run();
      return json({ ok: true });
    }
    const groupMembers = path.match(/^groups\/([^/]+)\/members$/);
    if (groupMembers && request.method === "GET") {
      await chatAllowed(env.DB, me.id, groupMembers[1]);
      const rows = await env.DB.prepare(
        `SELECT u.id,u.name,u.username,u.avatar_seed,u.avatar_style,u.status,u.is_online,gm.role,gm.can_post FROM group_members gm JOIN users u ON u.id=gm.user_id WHERE gm.chat_id=? ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,u.name LIMIT 200`,
      )
        .bind(groupMembers[1])
        .all<any>();
      return json({ members: rows.results || [] });
    }
    if (groupMembers && request.method === "POST") {
      await requireGroupAdmin(env.DB, me.id, groupMembers[1]);
      const body = await readJson<{ username: string }>(request);
      const username = normalizeUsername(
        assertString(body?.username, "username", 25),
      );
      const user = await env.DB.prepare("SELECT id FROM users WHERE username=?")
        .bind(username)
        .first<{ id: string }>();
      if (!user) throw new HttpError(404, "Пользователь не найден");
      if (
        await env.DB.prepare(
          "SELECT 1 FROM group_members WHERE chat_id=? AND user_id=?",
        )
          .bind(groupMembers[1], user.id)
          .first()
      )
        throw new HttpError(409, "Пользователь уже в группе", "CONFLICT");
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,?,?)",
        ).bind(groupMembers[1], user.id, "member", now()),
        env.DB.prepare(
          "INSERT INTO group_members(chat_id,user_id,role) VALUES(?,?,?)",
        ).bind(groupMembers[1], user.id, "member"),
      ]);
      return json({ ok: true });
    }
    const groupMember = path.match(/^groups\/([^/]+)\/members\/([^/]+)$/);
    if (groupMember && request.method === "DELETE") {
      await chatAllowed(env.DB, me.id, groupMember[1]);
      const actor = await groupRole(env.DB, me.id, groupMember[1]);
      const target = await groupRole(env.DB, groupMember[2], groupMember[1]);
      if (!actor)
        throw new HttpError(403, "Вы не состоите в этой группе", "FORBIDDEN");
      if (!target) throw new HttpError(404, "Участник не найден");
      const isSelf = groupMember[2] === me.id;
      if (isSelf) {
        if (actor.role === "owner") {
          const successor = await env.DB.prepare(
            "SELECT user_id FROM group_members WHERE chat_id=? AND user_id<>? ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END, rowid LIMIT 1",
          )
            .bind(groupMember[1], me.id)
            .first<{ user_id: string }>();
          if (successor) {
            await env.DB.batch([
              env.DB.prepare(
                "UPDATE group_members SET role='member' WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], me.id),
              env.DB.prepare(
                "UPDATE chat_members SET role='member' WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], me.id),
              env.DB.prepare(
                "UPDATE group_members SET role='owner' WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], successor.user_id),
              env.DB.prepare(
                "UPDATE chat_members SET role='owner' WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], successor.user_id),
              env.DB.prepare("UPDATE chats SET owner_id=? WHERE id=?").bind(
                successor.user_id,
                groupMember[1],
              ),
              env.DB.prepare(
                "DELETE FROM group_members WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], me.id),
              env.DB.prepare(
                "DELETE FROM chat_members WHERE chat_id=? AND user_id=?",
              ).bind(groupMember[1], me.id),
            ]);
            return json({ ok: true, successorId: successor.user_id });
          }
          await env.DB.prepare("DELETE FROM chats WHERE id=?")
            .bind(groupMember[1])
            .run();
          return json({ ok: true, deleted: true });
        }
      } else {
        if (!["owner", "admin"].includes(actor.role))
          throw new HttpError(403, "Недостаточно прав", "FORBIDDEN");
        if (actor.role !== "owner" && target.role !== "member")
          throw new HttpError(
            403,
            "Администратор может удалить только обычного участника",
            "FORBIDDEN",
          );
      }
      await env.DB.batch([
        env.DB.prepare(
          "DELETE FROM group_members WHERE chat_id=? AND user_id=?",
        ).bind(groupMember[1], groupMember[2]),
        env.DB.prepare(
          "DELETE FROM chat_members WHERE chat_id=? AND user_id=?",
        ).bind(groupMember[1], groupMember[2]),
      ]);
      return json({ ok: true });
    }
    const groupAdmins = path.match(/^groups\/([^/]+)\/admins$/);
    if (groupAdmins && request.method === "POST") {
      await requireGroupAdmin(env.DB, me.id, groupAdmins[1], true);
      const body = await readJson<{ userId: string }>(request);
      const target = await groupRole(
        env.DB,
        body?.userId || "",
        groupAdmins[1],
      );
      if (!target) throw new HttpError(404, "Участник не найден");
      if (target.role === "owner")
        throw new HttpError(400, "Владелец уже имеет максимальные права");
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE group_members SET role='admin' WHERE chat_id=? AND user_id=?",
        ).bind(groupAdmins[1], body!.userId),
        env.DB.prepare(
          "UPDATE chat_members SET role='admin' WHERE chat_id=? AND user_id=?",
        ).bind(groupAdmins[1], body!.userId),
      ]);
      return json({ ok: true });
    }
    if (groupAdmins && request.method === "DELETE") {
      await requireGroupAdmin(env.DB, me.id, groupAdmins[1], true);
      const body = await readJson<{ userId: string }>(request);
      const target = await groupRole(
        env.DB,
        body?.userId || "",
        groupAdmins[1],
      );
      if (!target) throw new HttpError(404, "Участник не найден");
      if (target.role === "owner")
        throw new HttpError(400, "Нельзя снять владельца");
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE group_members SET role='member' WHERE chat_id=? AND user_id=?",
        ).bind(groupAdmins[1], body!.userId),
        env.DB.prepare(
          "UPDATE chat_members SET role='member' WHERE chat_id=? AND user_id=?",
        ).bind(groupAdmins[1], body!.userId),
      ]);
      return json({ ok: true });
    }
    const groupOwner = path.match(/^groups\/([^/]+)\/owner$/);
    if (groupOwner && request.method === "POST") {
      await requireGroupAdmin(env.DB, me.id, groupOwner[1], true);
      const body = await readJson<{ userId: string }>(request);
      const target = await groupRole(env.DB, body?.userId || "", groupOwner[1]);
      if (!target)
        throw new HttpError(
          404,
          "Новый владелец должен быть участником группы",
        );
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE group_members SET role='admin' WHERE chat_id=? AND user_id=?",
        ).bind(groupOwner[1], me.id),
        env.DB.prepare(
          "UPDATE chat_members SET role='admin' WHERE chat_id=? AND user_id=?",
        ).bind(groupOwner[1], me.id),
        env.DB.prepare(
          "UPDATE group_members SET role='owner' WHERE chat_id=? AND user_id=?",
        ).bind(groupOwner[1], body!.userId),
        env.DB.prepare(
          "UPDATE chat_members SET role='owner' WHERE chat_id=? AND user_id=?",
        ).bind(groupOwner[1], body!.userId),
        env.DB.prepare("UPDATE chats SET owner_id=? WHERE id=?").bind(
          body!.userId,
          groupOwner[1],
        ),
      ]);
      return json({ ok: true });
    }
    if (path === "groups" && request.method === "POST") {
      const body = await readJson<{
        name: string;
        description?: string;
        memberUsernames?: string[];
      }>(request);
      const name = assertString(body?.name, "name", 80),
        cid = id(),
        t = now();
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO chats(id,kind,title,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        ).bind(cid, "group", name, me.id, t, t),
        env.DB.prepare(
          "INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,?,?)",
        ).bind(cid, me.id, "owner", t),
        env.DB.prepare(
          "INSERT INTO groups(chat_id,description,avatar_seed) VALUES(?,?,?)",
        ).bind(cid, body?.description || "", cid),
        env.DB.prepare(
          "INSERT INTO group_members(chat_id,user_id,role) VALUES(?,?,?)",
        ).bind(cid, me.id, "owner"),
      ]);
      for (const raw of (body?.memberUsernames || []).slice(0, 50)) {
        const u = await env.DB.prepare("SELECT id FROM users WHERE username=?")
          .bind(normalizeUsername(raw))
          .first<{ id: string }>();
        if (u && u.id !== me.id)
          await env.DB.batch([
            env.DB.prepare(
              "INSERT OR IGNORE INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,?,?)",
            ).bind(cid, u.id, "member", t),
            env.DB.prepare(
              "INSERT OR IGNORE INTO group_members(chat_id,user_id,role) VALUES(?,?,?)",
            ).bind(cid, u.id, "member"),
          ]);
      }
      return json({ chatId: cid }, 201);
    }
    if (path === "ai" && request.method === "POST") {
      const body = await readJson<{ message: string }>(request);
      const text = assertString(body?.message, "message", 2000);
      if (!env.AI_ENDPOINT)
        return json(
          {
            error:
              "AI provider не настроен. Добавьте AI_ENDPOINT и AI_MODEL в Cloudflare secrets.",
          },
          503,
        );
      const upstream = await fetch(env.AI_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: env.AI_MODEL,
          messages: [{ role: "user", content: text }],
        }),
      });
      if (!upstream.ok)
        return json({ error: "AI provider временно недоступен" }, 502);
      const payload = await upstream.json<any>();
      return json({
        message: payload.choices?.[0]?.message?.content || payload.output || "",
      });
    }
    if (path === "events" && request.method === "GET") {
      const eventChatId = url.searchParams.get("chatId") || "";
      await chatAllowed(env.DB, me.id, eventChatId);
      const encoder = new TextEncoder();
      let closed = false;
      const stream = new ReadableStream({
        start(controller) {
          let lastMessageId = "";
          let busy = false;
          const send = async () => {
            if (closed) return;
            if (busy) return;
            busy = true;
            try {
              const latest = await env.DB.prepare(
                "SELECT id,created_at FROM messages WHERE chat_id=? ORDER BY created_at DESC LIMIT 1",
              )
                .bind(eventChatId)
                .first<{ id: string; created_at: string }>();
              if (latest?.id && latest.id !== lastMessageId) {
                lastMessageId = latest.id;
                controller.enqueue(
                  encoder.encode(
                    `event: message\ndata: ${JSON.stringify(latest)}\n\n`,
                  ),
                );
              } else {
                controller.enqueue(
                  encoder.encode(
                    `event: ping\ndata: ${JSON.stringify({ time: now() })}\n\n`,
                  ),
                );
              }
            } catch {}
            busy = false;
          };
          send();
          const timer = setInterval(send, 2500);
          setTimeout(() => {
            closed = true;
            clearInterval(timer);
            try {
              controller.close();
            } catch {}
          }, 25000);
        },
      });
      return new Response(stream, {
        headers: {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        },
      });
    }
    return json({ error: "Маршрут не найден" }, 404);
  } catch (e) {
    if (e instanceof HttpError)
      return json({ error: e.message, code: e.code }, e.status);
    console.error(e);
    return json({ error: "Внутренняя ошибка CloudGram" }, 500);
  }
};
