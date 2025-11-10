// _worker.js: Cloudflare Worker D1 数据库集成版本
// [!!!] 此版本集成了真实支付逻辑，移除了所有支付相关的伪代码。
// 它依赖于一个“非托管型”支付网关（您自己部署在 Fly.io 或其他地方）。
// 它使用 Web Crypto API (Workers 自带) 来验证 Webhook 签名。

import { Router } from 'itty-router';

const router = Router();

// --- 工具函数 ---
const json = (data, options = {}) => new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    status: options.status || 200,
});
const error = (status, message) => json({ success: false, message }, { status });

function parseCardSecret(fullSecret) {
    const regex = /(.*?)#\[(.*?)]#$/;
    const match = fullSecret.trim().match(regex);
    if (match && match[1] !== undefined && match[2] !== undefined) {
        return { secret: match[1].trim(), preset: match[2].trim() };
    }
    return { secret: fullSecret.trim(), preset: null };
}

// --- [!!! 关键修改 !!!] 支付网关辅助函数 (真实实现) ---

// 1. 从 D1 获取所有支付设置
async function getPaymentSettings(env) {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT key, value FROM PaymentSettings").all();
        return results.reduce((acc, row) => {
            acc[row.key] = row.value;
            return acc;
        }, {});
    } catch (e) {
        console.error("获取支付设置失败:", e);
        return {};
    }
}

// 2. [!!! 关键修改 !!!] 创建支付会话 (真实 API 调用)
// 此函数调用您部署在 Fly.io 上的“非托管型”网关
async function createPaymentSession(env, order, settings) {
    const { order_id, total_amount, product_name } = order;

    // 假设我们只处理自托管的 USDT 网关
    // (您可以扩展此逻辑以处理 settings.default_gateway 中的 Stripe 等)
    
    const gatewayUrl = settings.crypto_gateway_url;
    const apiKey = settings.crypto_api_key;
    
    if (!gatewayUrl || !apiKey) {
        throw new Error('后台未配置“自托管网关 URL”或“网关 API 密钥”');
    }

    // [!!!] 这是对您自托管网关的真实 API 调用
    // (请根据您的网关文档调整 /create_order 路径和 body)
    try {
        const response = await fetch(`${gatewayUrl}/create_order`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // 使用 API Key 验证 Worker -> Gateway 的请求
                'Authorization': `Bearer ${apiKey}` 
            },
            body: JSON.stringify({
                order_id: order_id,         // 您的内部订单 ID
                amount: total_amount,       // 金额
                currency: "USD",            // (或 CNY)
                product_name: product_name,
                // [!!] 关键：告诉网关支付成功后通知您哪里
                notify_url: `https://${env.WORKER_URL}/api/payment/notify/usdt_gateway`,
                return_url: `https://${env.SITE_URL}/pay.html?order_id=${order_id}`
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(`支付网关创建订单失败: ${errData.message || response.statusText}`);
        }
        
        const data = await response.json();
        
        // 假设网关返回支付 URL 或二维码内容
        return {
            payment_url: data.payment_url,
            qr_code_content: data.qr_code_content,
            payment_id: data.gateway_order_id // 网关的订单 ID
        };
        
    } catch (e) {
        console.error("调用自托管网关失败:", e);
        throw new Error(`调用支付网关失败: ${e.message}`);
    }
}

// 3. [!!! 关键新增 !!!] Webhook 签名验证
// 使用 Web Crypto API 验证 HMAC-SHA256 签名
async function verifyWebhookSignature(secret, body, signatureHeader) {
    if (!secret || !body || !signatureHeader) {
        return false;
    }
    
    try {
        // 1. 准备密钥
        const key = await crypto.subtle.importKey(
            "raw",
            (new TextEncoder()).encode(secret),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["verify"]
        );

        // 2. 准备签名 (假设签名是 Hex 编码的)
        const signatureBytes = Uint8Array.from(signatureHeader.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
        
        // 3. 准备数据
        const data = (new TextEncoder()).encode(body);

        // 4. 验证
        const isValid = await crypto.subtle.verify(
            "HMAC",
            key,
            signatureBytes,
            data
        );
        
        return isValid;
    } catch (e) {
        console.error("签名验证出错:", e);
        return false;
    }
}


// --- 认证中间件 ---
const withAuth = async (request, env) => {
    // ... (保持不变) ...
    const authHeader = request.headers.get('Authorization');
    const adminToken = env.ADMIN_TOKEN;
    if (!authHeader || !adminToken) {
        return error(401, '未授权: 缺少认证信息');
    }
    const [scheme, token] = authHeader.split(' ');
    if (scheme.toLowerCase() !== 'bearer' || token !== adminToken) {
        return error(401, '未授权: 无效的 Token');
    }
};

// --- API 路由 (登录) ---
router.post('/api/auth/login', async (request, env) => {
    // ... (保持不变) ...
    const { username, password } = await request.json();
    if (username === env.ADMIN_USER && password === env.ADMIN_PASS) {
        return json({ token: env.ADMIN_TOKEN });
    }
    return error(401, '用户名或密码错误');
});

// --- 公共 API 路由 ---

// ... (GET /api/categories, /api/products, /api/products/:id, /api/articles, /api/articles/:slug 保持不变) ...
// 获取所有分类
router.get('/api/categories', async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            "SELECT id, name, slug FROM Categories"
        ).all();
        return json(results);
    } catch (e) {
        return error(500, '获取分类失败: ' + e.message);
    }
});

// 获取所有商品列表 (公共)
router.get('/api/products', async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            "SELECT id, name, short_description, base_price, image_url FROM Products WHERE is_active = 1 ORDER BY sort_weight DESC"
        ).all();
        return json(results);
    } catch (e) {
        return error(500, '获取商品列表失败: ' + e.message);
    }
});

// 获取单个商品详情 (公共)
router.get('/api/products/:id', async ({ params }, env) => {
    try {
        const product = await env.MY_HLTX.prepare(
            "SELECT * FROM Products WHERE id = ?1 AND is_active = 1"
        ).bind(params.id).first();

        if (!product) return error(404, 'Product not found or not active');
        
        const { results: variants } = await env.MY_HLTX.prepare(
            `SELECT id, name, price_adjustment, stock_count, 
                    addon_price, wholesale_config 
             FROM ProductVariants 
             WHERE product_id = ?1`
        ).bind(params.id).all();
        
        product.variants = variants;
        
        delete product.variants_json;
        delete product.addon_price; 
        delete product.wholesale_config;
        
        return json(product);
    } catch (e) {
        return error(500, '获取商品详情失败: ' + e.message);
    }
});

// 获取文章列表
router.get('/api/articles', async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            "SELECT id, title, slug, summary, created_at FROM Articles ORDER BY created_at DESC"
        ).all();
        return json(results);
    } catch (e) {
        return error(500, '获取文章列表失败: ' + e.message);
    }
});

// 获取单个文章详情
router.get('/api/articles/:slug', async ({ params }, env) => {
    try {
        const article = await env.MY_HLTX.prepare(
            "SELECT id, title, slug, summary, content, created_at FROM Articles WHERE slug = ?1"
        ).bind(params.slug).first();

        if (!article) return error(404, 'Article not found');
        return json(article);
    } catch (e) {
        return error(500, '获取文章详情失败: ' + e.message);
    }
});

// --- [关键修改] 创建订单 ---
router.post('/api/orders', async (request, env) => {
    const { variant_id, custom_info } = await request.json();
    const variantIdInt = parseInt(variant_id);

    if (isNaN(variantIdInt)) return error(400, 'Invalid variant ID');

    try {
        // ... (查询商品和规格的逻辑保持不变) ...
        const { results: variantResults } = await env.MY_HLTX.prepare(`
            SELECT 
                pv.price_adjustment, pv.stock_count, pv.addon_price, 
                p.id AS product_id, p.base_price, 
                p.name AS product_name, pv.name AS variant_name
            FROM ProductVariants pv
            JOIN Products p ON pv.product_id = p.id
            WHERE pv.id = ?1
        `).bind(variantIdInt).all();
        
        if (variantResults.length === 0) return error(404, 'Variant not found');
        const variant = variantResults[0];

        if (variant.stock_count <= 0) {
            return error(400, '库存不足');
        }

        const totalAmount = variant.base_price + variant.price_adjustment + (variant.addon_price || 0);
        const orderId = `D1-${Date.now()}`;
        
        // 插入 'pending' 订单
        await env.MY_HLTX.prepare(`
            INSERT INTO Orders (id, variant_id, total_amount, status)
            VALUES (?1, ?2, ?3, 'pending')
        `).bind(orderId, variantIdInt, totalAmount).run();
        
        // --- [!!! 关键修改 !!!] 调用真实支付网关 ---
        // 1. 准备 Worker URL 和 站点 URL (用于回调)
        const workerEnv = {
            WORKER_URL: request.headers.get('host'),
            SITE_URL: request.headers.get('origin')
        };
        // 2. 获取支付设置
        const paymentSettings = await getPaymentSettings(env);
        // 3. 准备订单详情
        const orderDetails = {
            order_id: orderId,
            product_name: `${variant.product_name} - ${variant.variant_name}`,
            total_amount: totalAmount,
        };
        
        // 4. [!!!] 这是真实 API 调用，不再是伪代码
        const paymentInfo = await createPaymentSession(workerEnv, orderDetails, paymentSettings);
        
        // 5. 更新订单的 payment_id
        if (paymentInfo.payment_id) {
            await env.MY_HLTX.prepare("UPDATE Orders SET payment_id = ?1 WHERE id = ?2")
                .bind(paymentInfo.payment_id, orderId).run();
        }
        
        // 6. 返回支付信息给前端
        const newOrderResponse = {
            ...orderDetails,
            status: 'pending', 
            payment_url: paymentInfo.payment_url,
            qr_code_content: paymentInfo.qr_code_content
        };

        return json(newOrderResponse);
    } catch (e) {
        return error(500, `创建订单失败: ${e.message}`);
    }
});


// 获取订单详情 (用于前端轮询)
router.get('/api/orders/:id', async ({ params }, env) => {
    // ... (保持不变, 已包含 'paid' 状态检查) ...
    try {
        const order = await env.MY_HLTX.prepare(
            "SELECT o.id, o.status, o.delivered_card, c.preset_info " +
            "FROM Orders o " +
            "LEFT JOIN Cards c ON o.delivered_card = c.card_key AND o.variant_id = c.variant_id " +
            "WHERE o.id = ?1"
        ).bind(params.id).first();

        if (!order) return error(404, 'Order not found');
        
        if (order.status === 'paid') {
            return json({
                order_id: order.id,
                status: order.status,
                delivered_card: order.delivered_card,
                preset_info: order.preset_info
            });
        }
        
        return json({
            order_id: order.id,
            status: order.status
        });
        
    } catch (e) {
        return error(500, '获取订单详情失败: ' + e.message);
    }
});


// --- [!!! 关键修改 !!!] 支付回调 (WEBHOOK) (真实实现) ---
router.post('/api/payment/notify/:gateway', async ({ params, request, env }) => {
    const gateway = params.gateway;
    const db = env.MY_HLTX;

    try {
        // --- 1. [!!!] 验证签名 (真实实现) ---
        const settings = await getPaymentSettings(env);
        const secret = settings.crypto_webhook_secret; // (您在后台填写的 Webhook 密钥)
        
        // (假设网关在 X-Signature Header 中发送 HMAC-SHA256 签名)
        const signatureHeader = request.headers.get('X-Signature');
        const body = await request.clone().text(); // 必须克隆才能读取 body
        
        const isValid = await verifyWebhookSignature(secret, body, signatureHeader);
        
        if (!isValid) {
            console.error(`[Webhook] 网关 ${gateway} 签名验证失败`);
            return error(401, 'Invalid Signature');
        }

        // --- 2. 解析回调数据 (签名验证通过) ---
        const parsedBody = JSON.parse(body); // body 已经被读取为 text, 这里解析
        console.log(`[Webhook] 收到 ${gateway} 已验证的回调:`, parsedBody);
        
        // (!! 这里的解析逻辑取决于您的网关 !!)
        const order_id = parsedBody.order_id; // (您在创建时传入的ID)
        const payment_status = parsedBody.status === 'completed' ? 'success' : 'failed';

        if (payment_status === 'success') {
            
            // --- 3. [核心] 发放卡密 (逻辑保持不变) ---
            
            const order = await db.prepare("SELECT id, variant_id, status FROM Orders WHERE id = ?1").bind(order_id).first();
            if (!order) {
                console.error(`[Webhook] 订单 ${order_id} 未找到`);
                return error(404, 'Order not found');
            }
            if (order.status !== 'pending') {
                 console.log(`[Webhook] 订单 ${order_id} 状态为 ${order.status} (非 pending)，跳过。`);
                 return json({ received: true, message: "Duplicate or processed" });
            }
            
            const availableCard = await db.prepare(
                `SELECT id, card_key FROM Cards 
                 WHERE variant_id = ?1 AND is_used = 0 LIMIT 1`
            ).bind(order.variant_id).first();
            
            if (!availableCard) {
                console.error(`[!!!紧急!!!] 订单 ${order_id} 支付成功，但库存不足 (variant_id: ${order.variant_id})`);
                await db.prepare("UPDATE Orders SET status = 'failed', notes = 'Stock unavailable' WHERE id = ?1").bind(order_id).run();
                return error(500, 'Stock unavailable after payment');
            }
            
            // [事务] 更新数据库
            console.log(`[Webhook] 正在为订单 ${order_id} 发放卡密 (ID: ${availableCard.id})`);
            await db.batch([
                db.prepare("UPDATE Cards SET is_used = 1, used_at = datetime('now') WHERE id = ?1").bind(availableCard.id),
                db.prepare("UPDATE Orders SET status = 'paid', delivered_card = ?1 WHERE id = ?2").bind(availableCard.card_key, order_id),
                db.prepare("UPDATE ProductVariants SET stock_count = stock_count - 1 WHERE id = ?1").bind(order.variant_id)
            ]);
            console.log(`[Webhook] 订单 ${order_id} 处理成功。`);
        }
        
        // 4. 向支付网关返回成功
        return json({ received: true });
        
    } catch (e) {
        console.error(`[Webhook] ${gateway} 回调处理失败:`, e);
        return error(500, 'Webhook error: ' + e.message);
    }
});
// --- [新增 Webhook 结束] ---


// --- 后台管理 API 路由 (Admin API Routes) ---

// ... (所有 /api/admin/... 路由保持不变) ...
// (GET /api/admin/products)
router.get('/api/admin/products', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            "SELECT id, name, base_price, stock, is_active, sort_weight FROM Products ORDER BY id DESC"
        ).all();
        const finalResults = results.map(p => ({
            ...p,
            sold: p.sold || 0
        }));
        return json(finalResults);
    } catch (e) {
        return error(500, '获取商品列表失败: ' + e.message);
    }
});

// (POST /api/admin/products)
router.post('/api/admin/products', withAuth, async (request, env) => {
    
    const body = await request.json();
    const { 
        name, description, variants, 
        category_id, ...otherData 
    } = body;
    
    if (!name) return error(400, '商品名称是必填项');
    if (!variants || !Array.isArray(variants) || variants.length === 0) {
        return error(400, '至少需要一个商品规格');
    }
    if (!category_id) return error(400, '所属分类是必填项');

    const firstVariant = variants[0];
    const base_price = parseFloat(firstVariant.price);
    const stock = parseInt(firstVariant.stock) || 0;
    
    const isActiveInt = otherData.is_active ? 1 : 0;
    let variantsJson = JSON.stringify(variants); 

    const db = env.MY_HLTX;

    try {
        // --- 1. 插入主表 Products ---
        const stmt = db.prepare(
            `INSERT INTO Products (
                name, description, base_price, image_url, variants_json, 
                short_description, keywords, category_id, stock, 
                sort_weight, is_active
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
        );
        
        await stmt.bind(
            name, description, base_price,
            otherData.image_url || '', variantsJson,
            otherData.short_description || '', otherData.keywords || '',
            parseInt(category_id), stock,
            parseInt(otherData.sort_weight) || 0,
            isActiveInt
        ).run();

        const result = await db.prepare("SELECT last_insert_rowid() as id").first();
        const newProductId = result.id;

        // --- 2. 插入规格表 ProductVariants ---
        const variantStmts = variants.map(variant => {
            return db.prepare(
                `INSERT INTO ProductVariants (
                    product_id, name, price_adjustment, stock_count,
                    addon_price, wholesale_config 
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
            ).bind(
                newProductId,
                variant.name,
                parseFloat(variant.price) - base_price, 
                variant.stock_count || 0,
                parseFloat(variant.addon_price) || 0, 
                variant.wholesale_config || ''
            );
        });
        
        await db.batch(variantStmts);

        return json({ id: newProductId, success: true }, { status: 201 });
    } catch (e) {
        console.error("D1 Insert Error:", e);
        return error(500, '创建商品失败: ' + e.message); 
    }
});

// (DELETE /api/admin/products/:id)
router.delete('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    const db = env.MY_HLTX;
    try {
        await db.prepare("DELETE FROM Products WHERE id = ?1").bind(params.id).run();
        return json({ success: true });
    } catch (e) {
        return error(500, '删除商品失败: ' + e.message);
    }
});

// (GET /api/admin/products/:id)
router.get('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    try {
        const productId = params.id;
        const db = env.MY_HLTX;
        
        const product = await db.prepare(
            "SELECT * FROM Products WHERE id = ?1"
        ).bind(productId).first();

        if (!product) return error(404, '商品未找到');

        const { results: pv_data } = await db.prepare(
            `SELECT id, name, price_adjustment, stock_count, 
                    addon_price, wholesale_config 
             FROM ProductVariants 
             WHERE product_id = ?1`
        ).bind(productId).all();

        const variants_from_json = JSON.parse(product.variants_json || '[]');
        
        const pv_map = new Map(pv_data.map(v => [v.id, v]));
        const final_variants = [];

        if (variants_from_json.length >= pv_data.length && variants_from_json.length > 0) {
             for (let i = 0; i < variants_from_json.length; i++) {
                 const json_variant = variants_from_json[i];
                 const pv_variant = (json_variant.id && pv_map.get(json_variant.id)) ? 
                                    pv_map.get(json_variant.id) : 
                                    pv_data[i]; 
                 
                 if (!pv_variant) continue; 
                 
                 final_variants.push({
                     ...json_variant, 
                     ...pv_variant, 
                     price: product.base_price + pv_variant.price_adjustment
                 });
             }
        }
        
        if (final_variants.length === 0) {
            product.variants = pv_data.map(v => ({
                ...v,
                price: product.base_price + v.price_adjustment
            }));
        } else {
            product.variants = final_variants;
        }

        delete product.variants_json; 
        return json(product);

    } catch (e) {
        return error(500, '获取商品详情失败: ' + e.message);
    }
});

// (PUT /api/admin/products/:id)
router.put('/api/admin/products/:id', withAuth, async ({ params, request }, env) => {
    const productId = params.id;
    const db = env.MY_HLTX;
    
    const body = await request.json();
    const { 
        name, description, variants, 
        category_id, ...otherData 
    } = body;

    if (!name) return error(400, '商品名称是必填项');
    if (!variants || !Array.isArray(variants) || variants.length === 0) {
        return error(400, '至少需要一个商品规格');
    }
    if (!category_id) return error(400, '所属分类是必填项');
    
    const firstVariant = variants[0];
    const base_price = parseFloat(firstVariant.price);
    const stock = parseInt(firstVariant.stock) || 0; 
    const isActiveInt = otherData.is_active ? 1 : 0;
    let variantsJson = JSON.stringify(variants);
    
    try {
        // --- 1. 更新主表 Products ---
        const stmt = db.prepare(
            `UPDATE Products SET
                name = ?1, description = ?2, base_price = ?3, image_url = ?4,
                variants_json = ?5, short_description = ?6, keywords = ?7,
                category_id = ?8, stock = ?9, sort_weight = ?10, is_active = ?11
            WHERE id = ?12`
        );
        await stmt.bind(
            name, description, base_price,
            otherData.image_url || '', variantsJson,
            otherData.short_description || '', otherData.keywords || '',
            parseInt(category_id), stock,
            parseInt(otherData.sort_weight) || 0,
            isActiveInt, productId
        ).run();

        // --- 2. 同步规格表 ProductVariants ---
        await db.prepare("DELETE FROM ProductVariants WHERE product_id = ?1").bind(productId).run();
        
        const variantStmts = variants.map(variant => {
            return db.prepare(
                `INSERT INTO ProductVariants (
                    product_id, name, price_adjustment, stock_count,
                    addon_price, wholesale_config
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
            ).bind(
                productId,
                variant.name,
                parseFloat(variant.price) - base_price,
                variant.stock_count || variant.stock || 0,
                parseFloat(variant.addon_price) || 0,
                variant.wholesale_config || ''
            );
        });

        await db.batch(variantStmts);

        return json({ id: productId, success: true });
    } catch (e) {
        console.error("D1 Update Error:", e);
        return error(500, '更新商品失败: ' + e.message); 
    }
});


// ... (GET /api/admin/articles)
router.get('/api/admin/articles', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            `SELECT a.id, a.title, a.slug, a.image_url, a.created_at, c.name as category_name 
             FROM Articles a 
             LEFT JOIN ArticleCategories c ON a.article_category_id = c.id 
             ORDER BY a.created_at DESC`
        ).all();
        return json(results);
    } catch (e) {
        return error(500, '获取文章列表失败: ' + e.message);
    }
});

// ... (POST /api/admin/articles)
router.post('/api/admin/articles', withAuth, async (request, env) => {
    const { title, slug, summary, content, image_url, article_category_id } = await request.json();
    if (!title || !slug || !content) return error(400, '标题、Slug 和内容是必填项');
    try {
        await env.MY_HLTX.prepare(
            "INSERT INTO Articles (title, slug, summary, content, image_url, article_category_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ).bind(title, slug, summary || '', content, image_url || '', article_category_id ? parseInt(article_category_id) : null).run();
        const result = await env.MY_HLTX.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建文章失败: ' + e.message);
    }
});

// ... (GET /api/admin/articles/:id)
router.get('/api/admin/articles/:id', withAuth, async ({ params }, env) => {
    try {
        const article = await env.MY_HLTX.prepare(
            "SELECT id, title, slug, summary, content, image_url, article_category_id FROM Articles WHERE id = ?1"
        ).bind(params.id).first();
        
        if (!article) return error(404, '文章未找到');
        return json(article);
    } catch (e) {
        return error(500, '获取文章详情失败: ' + e.message);
    }
});

// ... (PUT /api/admin/articles/:id)
router.put('/api/admin/articles/:id', withAuth, async ({ params, request }, env) => {
    const { title, slug, summary, content, image_url, article_category_id } = await request.json();
    if (!title || !slug || !content) return error(400, '标题、Slug 和内容是必填项');
    
    try {
        await env.MY_HLTX.prepare(
            "UPDATE Articles SET title = ?1, slug = ?2, summary = ?3, content = ?4, image_url = ?5, article_category_id = ?6 WHERE id = ?7"
        ).bind(title, slug, summary || '', content, image_url || '', article_category_id ? parseInt(article_category_id) : null, params.id).run();
        
        return json({ id: params.id, success: true });
    } catch (e) {
        return error(500, '更新文章失败: ' + e.message);
    }
});

// ... (DELETE /api/admin/articles/:id)
router.delete('/api/admin/articles/:id', withAuth, async ({ params }, env) => {
    try {
        await env.MY_HLTX.prepare(
            "DELETE FROM Articles WHERE id = ?1"
        ).bind(params.id).run();
        
        return json({ success: true });
    } catch (e) {
        return error(500, '删除文章失败: ' + e.message);
    }
});

// ... (GET /api/admin/categories)
router.get('/api/admin/categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM Categories").all();
        return json(results);
    } catch (e) {
        return error(500, '获取分类失败: ' + e.message);
    }
});

// ... (POST /api/admin/categories)
router.post('/api/admin/categories', withAuth, async (request, env) => {
    const { name, slug } = await request.json();
    if (!name || !slug) return error(400, '名称和Slug是必填项');
    try {
        await env.MY_HLTX.prepare(
            "INSERT INTO Categories (name, slug) VALUES (?1, ?2)"
        ).bind(name, slug).run();
        const result = await env.MY_HLTX.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建分类失败: ' + e.message);
    }
});

// ... (GET /api/admin/article_categories)
router.get('/api/admin/article_categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM ArticleCategories").all();
        return json(results);
    } catch (e) {
        return error(500, '获取文章分类失败: ' + e.message);
    }
});

// ... (POST /api/admin/article_categories)
router.post('/api/admin/article_categories', withAuth, async (request, env) => {
    const { name, slug } = await request.json();
    if (!name || !slug) return error(400, '名称和Slug是必填项');
    try {
        await env.MY_HLTX.prepare(
            "INSERT INTO ArticleCategories (name, slug) VALUES (?1, ?2)"
        ).bind(name, slug).run();
        const result = await env.MY_HLTX.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建文章分类失败: ' + e.message);
    }
});

// ... (DELETE /api/admin/article_categories/:id)
router.delete('/api/admin/article_categories/:id', withAuth, async ({ params }, env) => {
    try {
        const usage = await env.MY_HLTX.prepare(
            "SELECT id FROM Articles WHERE article_category_id = ?1 LIMIT 1"
        ).bind(params.id).first();

        if (usage) {
            return error(400, '删除失败：仍有文章在使用此分类，请先移除或修改相关文章。');
        }

        await env.MY_HLTX.prepare(
            "DELETE FROM ArticleCategories WHERE id = ?1"
        ).bind(params.id).run();
        
        return json({ success: true });
    } catch (e) {
        return error(500, '删除文章分类失败: ' + e.message);
    }
});

// ... (GET /api/admin/orders)
router.get('/api/admin/orders', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(`
            SELECT 
                o.id AS order_id, o.total_amount, o.status, o.created_at, 
                p.name AS product_name, pv.name AS variant_name
            FROM Orders o
            JOIN ProductVariants pv ON o.variant_id = pv.id
            JOIN Products p ON pv.product_id = p.id
            ORDER BY o.created_at DESC
        `).all();
        const formattedResults = results.map(o => ({
            ...o,
            product_name: `${o.product_name} - ${o.variant_name}`,
            variant_name: undefined 
        }));
        return json(formattedResults);
    } catch (e) {
        return error(500, '获取订单失败: ' + e.message);
    }
});

// ... (GET /api/admin/cards)
router.get('/api/admin/cards', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            `SELECT 
                c.id as card_id, c.card_key, c.preset_info, c.is_used, 
                c.created_at, c.variant_id,
                p.name AS product_name, 
                pv.name AS variant_name
            FROM Cards c
            LEFT JOIN ProductVariants pv ON c.variant_id = pv.id
            LEFT JOIN Products p ON pv.product_id = p.id
            ORDER BY c.id DESC`
        ).all();
        
        return json(results);
    } catch (e) {
        return error(500, '获取卡密列表失败: ' + e.message);
    }
});

// ... (POST /api/admin/cards)
router.post('/api/admin/cards', withAuth, handleAddCard);
async function handleAddCard(request, env) {
    try {
        const { variant_id, secret, is_sold } = await request.json();
        if (!variant_id || !secret) return error(400, '商品规格ID和卡密内容不能为空');
        const variant = await env.MY_HLTX.prepare("SELECT id FROM ProductVariants WHERE id = ?1").bind(variant_id).first();
        if (!variant) return error(404, '商品规格 (Variant) 未找到');
        const secrets = secret.split('\n').filter(s => s.trim().length > 0);
        if (secrets.length === 0) return error(400, '卡密内容不能为空');
        const db = env.MY_HLTX;
        const stmts = [];
        const now = new Date().toISOString();
        for (const sec of secrets) {
            const parsed = parseCardSecret(sec);
            stmts.push(
                db.prepare('INSERT INTO Cards (variant_id, card_key, preset_info, is_used, created_at) VALUES (?, ?, ?, ?, ?)')
                  .bind(variant_id, parsed.secret, parsed.preset, is_sold || 0, now)
            );
        }
        await db.batch(stmts);
        if ((is_sold || 0) === 0) {
             await env.MY_HLTX.prepare(
                "UPDATE ProductVariants SET stock_count = stock_count + ?1 WHERE id = ?2"
            ).bind(stmts.length, variant_id).run();
        }
        return json({ success: true, count: stmts.length }, { status: 201 });
    } catch (e) {
        return error(500, 'Internal Server Error: ' + e.message);
    }
}

// ... (POST /api/admin/cards/import)
router.post('/api/admin/cards/import', withAuth, async (request, env) => {
    const { variant_id: variantId, keys } = await request.json();
    const variant_id = parseInt(variantId);
    if (!variant_id || !keys || !Array.isArray(keys)) return error(400, '规格ID和卡密列表是必填项');
    try {
        const variant = await env.MY_HLTX.prepare("SELECT id FROM ProductVariants WHERE id = ?1").bind(variant_id).first();
        if (!variant) return error(404, 'Variant not found');
        let addedCount = 0;
        const insertCardStmt = env.MY_HLTX.prepare(
            "INSERT INTO Cards (variant_id, card_key, preset_info) VALUES (?1, ?2, ?3)"
        );
        const insertPromises = keys.map(key => {
            const parsed = parseCardSecret(key);
            return insertCardStmt.bind(variant_id, parsed.secret, parsed.preset).run();
        });
        const results = await Promise.allSettled(insertPromises);
        results.forEach(res => {
            if (res.status === 'fulfilled' && res.value && res.value.success) addedCount++;
        });
        await env.MY_HLTX.prepare(
            "UPDATE ProductVariants SET stock_count = stock_count + ?1 WHERE id = ?2"
        ).bind(addedCount, variant_id).run();
        return json({ success: true, added_count: addedCount }, { status: 201 });
    } catch (e) {
        return error(500, '导入卡密失败: ' + e.message);
    }
});

// ... (GET /api/admin/settings/payment)
router.get('/api/admin/settings/payment', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT key, value FROM PaymentSettings").all();
        const settings = results.reduce((acc, row) => {
            acc[row.key] = row.value;
            return acc;
        }, {});
        return json(settings);
    } catch (e) {
        return error(500, '获取支付设置失败: ' + e.message);
    }
});

// ... (POST /api/admin/settings/payment)
router.post('/api/admin/settings/payment', withAuth, async (request, env) => {
    const updates = await request.json();
    try {
        const promises = Object.entries(updates).map(([key, value]) => {
            // [!!!] 确保我们不会保存一个 'undefined' 值 (当密码未更改时)
            if (value === undefined) {
                return Promise.resolve();
            }
            return env.MY_HLTX.prepare(
                "REPLACE INTO PaymentSettings (key, value) VALUES (?1, ?2)"
            ).bind(key, value).run();
        });
        await Promise.all(promises);
        const { results } = await env.MY_HLTX.prepare("SELECT key, value FROM PaymentSettings").all();
        const newSettings = results.reduce((acc, row) => {
            acc[row.key] = row.value;
            return acc;
        }, {});
        return json({ success: true, settings: newSettings });
    } catch (e) {
        return error(500, '保存支付设置失败: ' + e.message);
    }
});

// ... (GET /api/admin/settings/config)
router.get('/api/admin/settings/config', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT key, value FROM Configurations").all();
        const configurations = results.reduce((acc, row) => {
            acc[row.key] = row.value;
            return acc;
        }, {});
        return json(configurations);
    } catch (e) {
        return error(500, '获取通用配置失败: ' + e.message);
    }
});

// ... (POST /api/admin/settings/config)
router.post('/api/admin/settings/config', withAuth, async (request, env) => {
    const updates = await request.json();
    try {
        const promises = Object.entries(updates).map(([key, value]) => {
            return env.MY_HLTX.prepare(
                "REPLACE INTO Configurations (key, value) VALUES (?1, ?2)"
            ).bind(key, value).run();
        });
        await Promise.all(promises);
        const { results } = await env.MY_HLTX.prepare("SELECT key, value FROM Configurations").all();
        const newConfigurations = results.reduce((acc, row) => {
            acc[row.key] = row.value;
            return acc;
        }, {});
        return json({ success: true, configurations: newConfigurations });
    } catch (e) {
        return error(500, '保存通用配置失败: ' + e.message);
    }
});


// --- 静态文件和路由处理 ---
router.all('*', (request, env) => env.ASSETS.fetch(request));

// --- Worker 入口 ---
export default {
    async fetch(request, env) {
        if (!env.MY_HLTX) {
            return error(500, "Worker配置错误: 缺少D1数据库绑定'MY_HLTX'");
        }
        return router.handle(request, env);
    }
};
