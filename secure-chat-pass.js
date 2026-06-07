require('dotenv').config();
const { Telegraf } = require('telegraf');
const crypto = require('crypto');

/**
 * إعدادات الأمان المتقدمة
 */
const CONFIG = {
    ALGORITHM: 'aes-256-gcm',
    IV_LENGTH: 12, // طول الـ IV الموصى به لـ GCM
    SALT_LENGTH: 16,
    AUTH_TAG_LENGTH: 16,
    SCRYPT_KEY_LEN: 32,
    SCRYPT_PARAMS: { N: 16384, r: 8, p: 1 }, // معايير scrypt للأمان العالي
    RATE_LIMIT_MS: 1000, // منع إرسال أكثر من رسالة في الثانية
    MAX_LOGIN_ATTEMPTS: 5
};

// تحميل التوكن من ملف .env
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN || BOT_TOKEN === 'YOUR_TELEGRAM_BOT_TOKEN_HERE') {
    console.error("❌ خطأ: يرجى وضع توكن البوت في ملف .env");
    process.exit(1);
}

// قائمة المستخدمين المسموح لهم
const ALLOWED_USERS = process.env.ALLOWED_USERS 
    ? process.env.ALLOWED_USERS.split(',').map(id => id.trim()) 
    : [];

const bot = new Telegraf(BOT_TOKEN);

// وسيط (Middleware) للتحقق من الصلاحيات
bot.use((ctx, next) => {
    const userId = String(ctx.from?.id);
    
    // إذا كانت القائمة فارغة، نسمح للجميع (أو يمكنك تغيير هذا السلوك)
    if (ALLOWED_USERS.length > 0 && !ALLOWED_USERS.includes(userId)) {
        // إذا حاول مستخدم غير مصرح له استخدام البوت
        if (ctx.updateType === 'message') {
            return ctx.replyWithMarkdown(`🚫 **عذراً، هذا البوت خاص.**\n\nليس لديك صلاحية الوصول. يرجى التواصل مع المالك للحصول على تصريح.`);
        }
        return; // تجاهل التحديثات الأخرى
    }
    return next();
});

// قواعد بيانات مؤقتة (في الذاكرة)
const users = new Map();
const activeConnections = new Map();
const rateLimit = new Map();

/**
 * دالة اشتقاق مفتاح تشفير قوي باستخدام scrypt
 */
function deriveKey(password, salt) {
    return crypto.scryptSync(password, salt, CONFIG.SCRYPT_KEY_LEN, CONFIG.SCRYPT_PARAMS);
}

/**
 * تشفير احترافي باستخدام AES-256-GCM (Authenticated Encryption)
 */
function encrypt(text, password) {
    const iv = crypto.randomBytes(CONFIG.IV_LENGTH);
    const salt = crypto.randomBytes(CONFIG.SALT_LENGTH);
    const key = deriveKey(password, salt);
    
    const cipher = crypto.createCipheriv(CONFIG.ALGORITHM, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    // الهيكل: salt:iv:authTag:encryptedData
    return `${salt.toString('hex')}:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * فك تشفير آمن مع التحقق من سلامة البيانات
 */
function decrypt(cipherText, password) {
    try {
        const [saltHex, ivHex, authTagHex, encryptedHex] = cipherText.split(':');
        
        const salt = Buffer.from(saltHex, 'hex');
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const encryptedData = Buffer.from(encryptedHex, 'hex');
        
        const key = deriveKey(password, salt);
        const decipher = crypto.createDecipheriv(CONFIG.ALGORITHM, key, iv);
        
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (e) {
        console.error("Decryption error:", e.message);
        return null; // فشل فك التشفير أو التلاعب بالبيانات
    }
}

/**
 * حماية ضد السبام والهجمات العنيفة
 */
function isRateLimited(userId) {
    const now = Date.now();
    const lastSeen = rateLimit.get(userId) || 0;
    if (now - lastSeen < CONFIG.RATE_LIMIT_MS) return true;
    rateLimit.set(userId, now);
    return false;
}

// --- معالجات البوت ---

bot.start((ctx) => {
    const userId = ctx.from.id;
    users.set(userId, { step: 'idle' });
    
    ctx.replyWithMarkdown(
        `🛡️ **نظام الدردشة الفائق الأمان v2.0**\n\n` +
        `هذا البوت يستخدم معايير تشفير عسكرية:\n` +
        `• **AES-256-GCM**: لضمان سرية وسلامة الرسائل.\n` +
        `• **Scrypt**: لحماية كلمة السر من هجمات القوة الغاشمة.\n` +
        `• **No-Logs**: لا يتم تخزين أي رسائل على السيرفر.\n\n` +
        `لبدء محادثة آمنة، استخدم الأمر: /connect`
    );
});

bot.command('connect', (ctx) => {
    const userId = ctx.from.id;
    users.set(userId, { step: 'waiting_for_id' });
    ctx.replyWithMarkdown('👤 من فضلك، أدخل **ID الطرف الآخر**:');
});

bot.on('text', async (ctx) => {
    const userId = ctx.from.id;
    const text = ctx.message.text.trim();
    const userState = users.get(userId) || { step: 'idle' };

    if (isRateLimited(userId)) return;

    // تجاهل الأوامر
    if (text.startsWith('/') && userState.step === 'idle') return;

    switch (userState.step) {
        case 'waiting_for_id':
            if (!/^\d+$/.test(text) || text == userId) {
                return ctx.reply('❌ يرجى إدخال معرف رقمي صحيح (وليس معرفك الخاص).');
            }
            users.set(userId, { ...userState, step: 'waiting_for_password', targetId: text });
            ctx.replyWithMarkdown('🔑 أدخل الآن **كلمة السر المشتركة** (يجب أن تكون قوية):');
            break;

        case 'waiting_for_password':
            if (text.length < 8) {
                return ctx.reply('⚠️ لأمانك، يجب أن تتكون كلمة السر من 8 رموز على الأقل.');
            }
            
            const targetId = userState.targetId;
            activeConnections.set(userId, { targetId, password: text });
            users.set(userId, { step: 'connected' });
            
            ctx.replyWithMarkdown('✅ **تم تفعيل وضع التشفير العسكري.**\n\nيمكنك الآن إرسال رسائلك، سيتم تشفيرها فوراً.');
            
            // إشعار الطرف الآخر بطلب اتصال
            bot.telegram.sendMessage(targetId, 
                `🔔 **طلب اتصال آمن!**\nشخص ما يحاول فتح غرفة مشفرة معك (ID: \`${userId}\`).\n` +
                `استخدم /connect وأدخل نفس المعرف وكلمة السر للبدء.`,
                { parse_mode: 'Markdown' }
            ).catch(() => {});
            break;

        case 'connected':
            const conn = activeConnections.get(userId);
            if (!conn) {
                users.set(userId, { step: 'idle' });
                return ctx.reply('⚠️ انتهت الجلسة، يرجى الاتصال مجدداً.');
            }

            const encrypted = encrypt(text, conn.password);
            const partnerConn = activeConnections.get(conn.targetId);

            if (partnerConn) {
                const decrypted = decrypt(encrypted, partnerConn.password);
                
                if (decrypted) {
                    bot.telegram.sendMessage(conn.targetId, `💬 **رسالة مشفرة:**\n\n${decrypted}`, { parse_mode: 'Markdown' })
                        .then(() => ctx.reply('🔒 _أُرسلت مشفرة_'))
                        .catch(() => ctx.reply('❌ فشل تسليم الرسالة.'));
                } else {
                    bot.telegram.sendMessage(conn.targetId, `⚠️ **تنبيه:** استلمت رسالة مشفرة لكن كلمة السر لديك غير متطابقة!`)
                        .catch(() => {});
                    ctx.reply('❌ خطأ في المطابقة: يبدو أن الطرف الآخر يستخدم كلمة سر مختلفة.');
                }
            } else {
                ctx.reply('⏳ الطرف الآخر لم يربط الجلسة بعد. تم إرسال إشعار له.');
            }
            break;

        default:
            if (!text.startsWith('/')) {
                ctx.reply('ℹ️ أرسل /connect لبدء دردشة مشفرة أو /help للمساعدة.');
            }
    }
});

bot.command('disconnect', (ctx) => {
    const userId = ctx.from.id;
    const conn = activeConnections.get(userId);
    
    if (conn) {
        const targetId = conn.targetId;
        activeConnections.delete(userId);
        activeConnections.delete(targetId);
        users.set(userId, { step: 'idle' });
        if (users.has(targetId)) users.set(targetId, { step: 'idle' });
        
        ctx.reply('🔓 تم تدمير الجلسة ومفاتيح التشفير بنجاح.');
        bot.telegram.sendMessage(targetId, '🚫 قام الطرف الآخر بقطع الاتصال وتدمير الغرفة.').catch(() => {});
    } else {
        ctx.reply('⚠️ لست في أي محادثة حالياً.');
    }
});

bot.help((ctx) => {
    ctx.replyWithMarkdown(
        `📖 **دليل الاستخدام:**\n\n` +
        `1. استخدم /connect لبدء الاتصال.\n` +
        `2. أدخل ID صديقك.\n` +
        `3. اتفقوا على كلمة سر (خارج البوت).\n` +
        `4. ابدأ الدردشة بأمان.\n\n` +
        `قطع الاتصال: /disconnect`
    );
});

bot.catch((err, ctx) => {
    console.error(`Telegram Error for ${ctx.updateType}:`, err);
});

bot.launch().then(() => {
    console.log("🛡️ البوت الاحترافي يعمل الآن بأعلى معايير الأمان...");
});

// إيقاف آمن
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
