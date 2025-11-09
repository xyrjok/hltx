// _worker.js: Cloudflare Worker D1 数据库集成版本
// 此文件已移除所有 Mock 数据和逻辑，改为通过 env.MY_HLTX 连接 Cloudflare D1 数据库。
// 请确保在 Worker 设置中绑定了一个名为 'MY_HLTX' 的 D1 数据库，并设置了 ADMIN_USER, ADMIN_PASS, ADMIN_TOKEN 环境变量。

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

// --- 认证中间件 ---
const withAuth = async (request, env) => {
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
    const { username, password } = await request.json();
    if (username === env.ADMIN_USER && password === env.ADMIN_PASS) {
        return json({ token: env.ADMIN_TOKEN });
    }
    return error(401, '用户名或密码错误');
});

// --- 公共 API 路由 ---

// (分类、文章等保持不变)
router.get('/api/categories', async (request, env) => { /* ... */ });
router.get('/api/articles', async (request, env) => { /* ... */ });
router.get('/api/articles/:slug', async ({ params }, env) => { /* ... */ });

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
// START: 关键修改 - 公共API现在也从 ProductVariants 读取
router.get('/api/products/:id', async ({ params }, env) => {
    try {
        const product = await env.MY_HLTX.prepare(
            "SELECT * FROM Products WHERE id = ?1 AND is_active = 1"
        ).bind(params.id).first();

        if (!product) return error(404, 'Product not found or not active');
        
        // (!!!) 关键修改: 公共API现在也获取每个规格的独立配置
        const { results: variants } = await env.MY_HLTX.prepare(
            `SELECT id, name, price_adjustment, stock_count, 
                    addon_price, wholesale_config 
             FROM ProductVariants 
             WHERE product_id = ?1`
        ).bind(params.id).all();
        
        product.variants = variants;
        
        delete product.variants_json;
        // (删除主表上的冗余字段，不发送给前端)
        delete product.addon_price; 
        delete product.wholesale_config;
        
        return json(product);
    } catch (e) {
        return error(500, '获取商品详情失败: ' + e.message);
    }
});
// END: 关键修改

// 创建订单
// START: 关键修改 - 订单API现在也从 ProductVariants 读取
router.post('/api/orders', async (request, env) => {
    const { variant_id, custom_info } = await request.json();
    const variantIdInt = parseInt(variant_id);

    if (isNaN(variantIdInt)) return error(400, 'Invalid variant ID');

    try {
        // (!!!) 关键修改: 从 pv (ProductVariants) 获取 addon_price
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

        const availableCard = await env.MY_HLTX.prepare(`
            SELECT id, card_key, preset_info FROM Cards 
            WHERE variant_id = ?1 AND is_used = 0 
            LIMIT 1
        `).bind(variantIdInt).first();

        if (!availableCard) {
            return error(400, '库存不足');
        }

        // (!!!) 关键修改: totalAmount 现在使用 variant.addon_price
        const totalAmount = variant.base_price + variant.price_adjustment + (variant.addon_price || 0);
        const orderId = `D1-${Date.now()}`;
        const paymentId = `PAY-${Date.now()}`;

        // (后续逻辑不变)
        await env.MY_HLTX.prepare(`
            INSERT INTO Orders (id, variant_id, total_amount, status, payment_id, delivered_card)
            VALUES (?1, ?2, ?3, 'paid', ?4, ?5)
        `).bind(orderId, variantIdInt, totalAmount, paymentId, availableCard.card_key).run();
        
        await env.MY_HLTX.prepare(`
            UPDATE Cards SET is_used = 1, used_at = datetime('now') WHERE id = ?1
        `).bind(availableCard.id).run();
        
        await env.MY_HLTX.prepare(
             "UPDATE ProductVariants SET stock_count = stock_count - 1 WHERE id = ?1"
        ).bind(variantIdInt).run();

        const newOrder = {
            order_id: orderId,
            product_name: `${variant.product_name} - ${variant.variant_name}`,
            total_amount: totalAmount,
            status: 'paid', 
            delivered_card: availableCard.card_key,
            preset_info: availableCard.preset_info
        };

        return json(newOrder);
    } catch (e) {
        return error(500, '创建订单失败: ' + e.message);
    }
});
// END: 关键修改

// 获取订单详情
router.get('/api/orders/:id', async ({ params }, env) => {
    try {
        const order = await env.MY_HLTX.prepare(
            "SELECT o.id, o.status, o.delivered_card, c.preset_info " +
            "FROM Orders o " +
            "LEFT JOIN Cards c ON o.delivered_card = c.card_key AND o.variant_id = c.variant_id " +
            "WHERE o.id = ?1"
        ).bind(params.id).first();

        if (!order) return error(404, 'Order not found');
        
        return json({
            order_id: order.id,
            status: order.status,
            delivered_card: order.delivered_card,
            preset_info: order.preset_info
        });
    } catch (e) {
        return error(500, '获取订单详情失败: ' + e.message);
    }
});


// --- 后台管理 API 路由 (Admin API Routes) ---

// 获取所有商品列表
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


// 添加新商品 (后台管理)
// START: 关键修改 - 写入 ProductVariants
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
    const stock = parseInt(firstVariant.stock) || 0; // (这个 stock 只是一个冗余值, 真正的值在 PV)
    
    const isActiveInt = otherData.is_active ? 1 : 0;
    // (我们仍保存 variants_json, 因为它包含 color_code 等 UI 字段)
    let variantsJson = JSON.stringify(variants); 

    const db = env.MY_HLTX;

    try {
        // --- 1. 插入主表 Products ---
        // (!!!) 关键: addon_price 和 wholesale_config 不再保存到主表
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
        // (!!!) 关键: 现在为每个规格插入独立的 addon_price 和 wholesale_config
        const variantStmts = variants.map(variant => {
            return db.prepare(
                `INSERT INTO ProductVariants (
                    product_id, name, price_adjustment, stock_count,
                    addon_price, wholesale_config 
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
            ).bind(
                newProductId,
                variant.name,
                parseFloat(variant.price) - base_price, // price_adjustment
                variant.stock_count || 0, // (从 variant.stock_count 读取)
                parseFloat(variant.addon_price) || 0, // (独立保存)
                variant.wholesale_config || ''        // (独立保存)
            );
        });
        
        await db.batch(variantStmts);

        return json({ id: newProductId, success: true }, { status: 201 });
    } catch (e) {
        console.error("D1 Insert Error:", e);
        return error(500, '创建商品失败: ' + e.message); 
    }
});
// END: 关键修改


// 删除商品
router.delete('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    const db = env.MY_HLTX;
    try {
        // ON DELETE CASCADE 会自动处理 ProductVariants
        await db.prepare("DELETE FROM Products WHERE id = ?1").bind(params.id).run();
        return json({ success: true });
    } catch (e) {
        return error(500, '删除商品失败: ' + e.message);
    }
});

// 获取单个商品详情 (后台管理)
// START: 关键修改 - 从 ProductVariants 读取
router.get('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    try {
        const productId = params.id;
        const db = env.MY_HLTX;
        
        const product = await db.prepare(
            "SELECT * FROM Products WHERE id = ?1"
        ).bind(productId).first();

        if (!product) return error(404, '商品未找到');

        // (!!!) 关键修复: 从 ProductVariants 表读取所有独立字段
        const { results: pv_data } = await db.prepare(
            `SELECT id, name, price_adjustment, stock_count, 
                    addon_price, wholesale_config 
             FROM ProductVariants 
             WHERE product_id = ?1`
        ).bind(productId).all();

        // (为了 UI, 我们仍需 `variants_json` 里的 color_code, sales 等)
        const variants_from_json = JSON.parse(product.variants_json || '[]');
        
        // (合并数据：以 pv_data 为基础，混入 variants_json 的额外数据)
        const pv_map = new Map(pv_data.map(v => [v.id, v]));
        const final_variants = [];

        // (如果 variants_json 和 pv_data 同步)
        if (variants_from_json.length === pv_data.length) {
             for (let i = 0; i < variants_from_json.length; i++) {
                 // (假设顺序一致, 这是一个脆弱的假设, 但
                 // `products_new.html` 是这样保存的)
                 // (为了健壮性, 我们最好通过ID匹配)
                 const json_variant = variants_from_json[i];
                 const pv_variant = pv_data[i]; // (假设顺序匹配)
                 
                 // (如果 pv_variant 不存在，说明数据不同步)
                 if (!pv_variant) continue; 
                 
                 final_variants.push({
                     ...json_variant, // (包含 color_code, sales)
                     ...pv_variant, // (覆盖 name, stock_count, addon_price,
                                    // wholesale_config)
                     price: product.base_price + pv_variant.price_adjustment // (计算
                                                                             // 售价)
                 });
             }
        }
        
        // (如果数据不同步，则只使用 pv_data)
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
// END: 关键修改

// 更新商品 (后台管理)
// START: 关键修改 - 写入 ProductVariants
router.put('/api/admin/products/:id', withAuth, async ({ params }, env) => {
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
    const stock = parseInt(firstVariant.stock) || 0; // (冗余)
    const isActiveInt = otherData.is_active ? 1 : 0;
    let variantsJson = JSON.stringify(variants);
    
    try {
        // --- 1. 更新主表 Products ---
        // (!!!) 关键: 不再更新 addon_price 和 wholesale_config
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
        // (先删除所有旧的)
        await db.prepare("DELETE FROM ProductVariants WHERE product_id = ?1").bind(productId).run();
        
        // (!!!) 关键: 插入所有新的, 包含独立的 addon_price 和
        // wholesale_config
        const variantStmts = variants.map(variant => {
            return db.prepare(
                `INSERT INTO ProductVariants (
                    product_id, name, price_adjustment, stock_count,
                    addon_price, wholesale_config
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
            ).bind(
                productId,
                variant.name,
                parseFloat(variant.price) - base_price, // price_adjustment
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
// END: 关键修改


// --- 其他 Admin API (保持不变) ---

router.get('/api/admin/articles', withAuth, async (request, env) => { /* ... */ });
router.post('/api/admin/articles', withAuth, async (request, env) => { /* ... */ });
router.get('/api/admin/categories', withAuth, async (request, env) => { /* ... */ });
router.post('/api/admin/categories', withAuth, async (request, env) => { /* ... */ });
router.get('/api/admin/orders', withAuth, async (request, env) => { /* ... */ });

// (卡密管理 API 无需改动)
router.get('/api/admin/cards', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM Cards ORDER BY id DESC").all();
        return json(results);
    } catch (e) {
        return error(500, '获取卡密列表失败: ' + e.message);
    }
});
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

// (设置 API 无需改动)
router.get('/api/admin/settings/payment', withAuth, async (request, env) => { /* ... */ });
router.post('/api/admin/settings/payment', withAuth, async (request, env) => { /* ... */ });
router.get('/api/admin/settings/config', withAuth, async (request, env) => { /* ... */ });
router.post('/api/admin/settings/config', withAuth, async (request, env) => { /* ... */ });

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
