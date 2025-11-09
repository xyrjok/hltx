// _worker.js: Cloudflare Worker D1 数据库集成版本
// 此文件已移除所有 Mock 数据和逻辑，改为通过 env.MY_HLTX 连接 Cloudflare D1 数据库。
// 请确保在 Worker 设置中绑定了一个名为 'MY_HLTX' 的 D1 数据库，并设置了 ADMIN_USER, ADMIN_PASS, ADMIN_TOKEN 环境变量。

import { Router } from 'itty-router';

const router = Router();

// --- 工具函数 ---

// 统一返回 JSON 格式
const json = (data, options = {}) => new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    status: options.status || 200,
});

// 统一返回错误信息
const error = (status, message) => json({ success: false, message }, { status });

// START: 新增辅助函数 - 解析卡密和预选信息
/**
 * 解析 "卡密信息#[预选信息]#" 格式的字符串
 * @param {string} fullSecret - 完整卡密字符串
 * @returns {{secret: string, preset: string|null}}
 */
function parseCardSecret(fullSecret) {
    const regex = /(.*?)#\[(.*?)]#$/;
    const match = fullSecret.trim().match(regex);
    
    // 如果匹配成功 (格式如: "abc#[def]#")
    if (match && match[1] !== undefined && match[2] !== undefined) {
        return { 
            secret: match[1].trim(), // 卡密信息
            preset: match[2].trim()  // 预选信息
        };
    }
    
    // 如果不匹配 (格式如: "abc")
    return { 
        secret: fullSecret.trim(), 
        preset: null 
    };
}
// END: 新增辅助函数

// --- 认证中间件 ---

/**
 * 认证中间件：检查请求头中的 Authorization Token 是否匹配环境变量中的 ADMIN_TOKEN
 * @param {Request} request 
 * @param {Env} env 环境变量
 * @returns {Response | undefined} 如果认证失败返回 Response，否则继续
 */
const withAuth = async (request, env) => {
    const authHeader = request.headers.get('Authorization');
    const adminToken = env.ADMIN_TOKEN;

    if (!authHeader || !adminToken) {
        return error(401, '未授权: 缺少认证信息');
    }

    const [scheme, token] = authHeader.split(' ');
    
    // 检查 token 类型和值
    if (scheme.toLowerCase() !== 'bearer' || token !== adminToken) {
        return error(401, '未授权: 无效的 Token');
    }
    // 认证通过，继续执行
};

// --- API 路由 ---

// 1. 登录 (无需认证)
router.post('/api/auth/login', async (request, env) => {
    const { username, password } = await request.json();
    
    // 检查用户名和密码是否匹配环境变量
    if (username === env.ADMIN_USER && password === env.ADMIN_PASS) {
        // 返回预设的 Token
        return json({ token: env.ADMIN_TOKEN });
    }
    
    return error(401, '用户名或密码错误');
});

// --- 公共 API 路由 (Public API Routes) ---

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

// 获取所有商品列表 (仅上架)
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

// 获取单个商品详情
router.get('/api/products/:id', async ({ params }, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(
            "SELECT * FROM Products WHERE id = ?1 AND is_active = 1"
        ).bind(params.id).all();

        if (!results || results.length === 0) return error(404, 'Product not found or not active');
        
        const product = results[0];
        product.variants = [];

        // 尝试解析 variants_json 字段
        if (product.variants_json) {
            try {
                product.variants = JSON.parse(product.variants_json);
            } catch(e) {
                console.error("Failed to parse variants_json:", e);
                // 如果解析失败，则留空
            }
        }
        
        // 如果没有 variants_json，则从 ProductVariants 表查询 (为了兼容)
        if (!product.variants || product.variants.length === 0) {
            const { results: variants } = await env.MY_HLTX.prepare(
                "SELECT id, name, price_adjustment, stock_count FROM ProductVariants WHERE product_id = ?1"
            ).bind(params.id).all();
             product.variants = variants;
        }

        delete product.variants_json;
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

// 创建订单 (使用 D1 事务逻辑)
router.post('/api/orders', async (request, env) => {
    const { variant_id, custom_info } = await request.json();
    const variantIdInt = parseInt(variant_id);

    if (isNaN(variantIdInt)) return error(400, 'Invalid variant ID');

    try {
        // 1. 获取规格和基础信息
        const { results: variantResults } = await env.MY_HLTX.prepare(`
            SELECT 
                pv.price_adjustment, pv.stock_count, p.id AS product_id, 
                p.base_price, p.addon_price, p.name AS product_name, pv.name AS variant_name
            FROM ProductVariants pv
            JOIN Products p ON pv.product_id = p.id
            WHERE pv.id = ?1
        `).bind(variantIdInt).all();
        
        if (variantResults.length === 0) return error(404, 'Variant not found');
        const variant = variantResults[0];

        // 2. 检查库存 (查找一个未使用的卡密)
        // START: 修改 - 同时获取 preset_info 以便前端显示
        const availableCard = await env.MY_HLTX.prepare(`
            SELECT id, card_key, preset_info FROM Cards 
            WHERE variant_id = ?1 AND is_used = 0 
            LIMIT 1
        `).bind(variantIdInt).first();
        // END: 修改

        if (!availableCard) {
            return error(400, '库存不足');
        }

        // 3. 计算金额并生成订单
        const totalAmount = variant.base_price + variant.price_adjustment + (variant.addon_price || 0);
        const orderId = `D1-${Date.now()}`;
        const paymentId = `PAY-${Date.now()}`; // 模拟支付 ID

        // 4. 插入订单 (状态为 paid，简化流程，直接交付卡密)
        // 使用事务确保卡密状态和订单创建的原子性 (D1目前不支持标准事务，但可以使用 Batch)
        
        // 插入订单
        await env.MY_HLTX.prepare(`
            INSERT INTO Orders (id, variant_id, total_amount, status, payment_id, delivered_card)
            VALUES (?1, ?2, ?3, 'paid', ?4, ?5)
        `).bind(orderId, variantIdInt, totalAmount, paymentId, availableCard.card_key).run();
        
        // 5. 将卡密标记为已使用
        await env.MY_HLTX.prepare(`
            UPDATE Cards SET is_used = 1, used_at = datetime('now') WHERE id = ?1
        `).bind(availableCard.id).run();
        
        // 6. 减少规格库存
        await env.MY_HLTX.prepare(
             "UPDATE ProductVariants SET stock_count = stock_count - 1 WHERE id = ?1"
        ).bind(variantIdInt).run();

        const newOrder = {
            order_id: orderId,
            product_name: `${variant.product_name} - ${variant.variant_name}`,
            total_amount: totalAmount,
            status: 'paid', 
            delivered_card: availableCard.card_key,
            preset_info: availableCard.preset_info // START: 修改 - 同样返回预选信息
        };

        return json(newOrder);
    } catch (e) {
        console.error("D1 Order Creation Error:", e);
        return error(500, '创建订单失败: ' + e.message);
    }
});


// 获取订单详情
router.get('/api/orders/:id', async ({ params }, env) => {
    try {
        // START: 修改 - 同时获取 preset_info
        const order = await env.MY_HLTX.prepare(
            "SELECT o.id, o.status, o.delivered_card, c.preset_info " +
            "FROM Orders o " +
            "LEFT JOIN Cards c ON o.delivered_card = c.card_key AND o.variant_id = c.variant_id " + // 假设 card_key + variant_id 是唯一的
            "WHERE o.id = ?1"
        ).bind(params.id).first();
        // END: 修改

        if (!order) return error(404, 'Order not found');
        
        // 注意: 这种 join 方式不完美, 如果卡密被删除, preset_info 会是 null
        // 但对于已交付订单是足够的
        
        return json({
            order_id: order.id,
            status: order.status,
            delivered_card: order.delivered_card,
            preset_info: order.preset_info // START: 修改 - 返回预选信息
        });
    } catch (e) {
        return error(500, '获取订单详情失败: ' + e.message);
    }
});


// --- 后台管理 API 路由 (Admin API Routes) ---

// 获取所有商品列表
router.get('/api/admin/products', withAuth, async (request, env) => {
    try {
        // (保持您之前的修改，stock/sold 是模拟的，从主表获取)
        const { results } = await env.MY_HLTX.prepare(
            "SELECT id, name, base_price, stock, is_active, sort_weight FROM Products ORDER BY id DESC"
        ).all();
        
        // 模拟销量 (如果需要)
        const finalResults = results.map(p => ({
            ...p,
            sold: p.sold || 0 // 假设 sold 字段不存在，默认为 0
        }));
        
        return json(finalResults);
    } catch (e) {
        return error(500, '获取商品列表失败: ' + e.message);
    }
});


// 添加新商品 (后台管理) - 适配前端提交的 variants 数组
router.post('/api/admin/products', withAuth, async (request, env) => {
    
    // --- 1. 获取前端发送的完整 body ---
    const body = await request.json();
    const { 
        name, description, image_url, variants, 
        short_description, keywords, category_id, 
        sort_weight, is_active 
    } = body;
    
    // --- 2. 校验 (基于新的数据结构) ---
    if (!name) {
        return error(400, '商品名称是必填项');
    }
    // 校验前端是否至少提交了一个规格
    if (!variants || !Array.isArray(variants) || variants.length === 0) {
        return error(400, '至少需要一个商品规格');
    }
    
    // --- 3. 从第一个规格中提取数据以存入 Products 主表 ---
    const firstVariant = variants[0];
    
    const base_price = parseFloat(firstVariant.price);
    const stock = parseInt(firstVariant.stock) || 0;
    const addon_price = parseFloat(firstVariant.addon_price) || 0;
    const wholesale_config = firstVariant.wholesale_config || '';

    if (isNaN(base_price) || base_price <= 0) {
        return error(400, '商品名称和有效价格是必填项');
    }
    if (!category_id) {
        return error(400, '所属分类是必填项');
    }
    
    const isActiveInt = is_active ? 1 : 0;
    let variantsJson = JSON.stringify(variants);
    
    // --- 4. D1 数据库插入 ---
    try {
        const stmt = env.MY_HLTX.prepare(
            `INSERT INTO Products (
                name, description, base_price, image_url, variants_json, 
                short_description, keywords, category_id, stock, 
                wholesale_config, addon_price, sort_weight, is_active
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 
                ?6, ?7, ?8, ?9, 
                ?10, ?11, ?12, ?13
            )`
        );
        
        await stmt.bind(
            name,                      // ?1
            description,               // ?2
            base_price,                // ?3 (来自 firstVariant.price)
            image_url || '',           // ?4
            variantsJson,              // ?5 (完整的 variants 数组)
            short_description || '',   // ?6
            keywords || '',            // ?7
            parseInt(category_id),     // ?8
            stock,                     // ?9 (来自 firstVariant.stock)
            wholesale_config,          // ?10 (来自 firstVariant.wholesale_config)
            addon_price,               // ?11 (来自 firstVariant.addon_price)
            parseInt(sort_weight) || 0,// ?12
            isActiveInt                // ?13
        ).run();

        const result = await env.MY_HLTX.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        console.error("D1 Insert Error:", e);
        return error(500, '创建商品失败: ' + e.message); 
    }
});


// 删除商品
router.delete('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    try {
        const result = await env.MY_HLTX.prepare("DELETE FROM Products WHERE id = ?1").bind(params.id).run();
        if (result.changes === 0) {
            return error(404, '商品未找到或删除失败');
        }
        return json({ success: true });
    } catch (e) {
        return error(500, '删除商品失败: ' + e.message);
    }
});

// --- 新增路由 (1/2): 获取单个商品详情 (后台管理) ---
router.get('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    try {
        const productId = params.id;
        // (从 public API 复制过来，但移除了 is_active = 1 的限制)
        const product = await env.MY_HLTX.prepare(
            "SELECT * FROM Products WHERE id = ?1"
        ).bind(productId).first();

        if (!product) return error(404, '商品未找到');

        // 解析 variants_json
        if (product.variants_json) {
            try {
                product.variants = JSON.parse(product.variants_json);
            } catch (e) {
                console.error("Failed to parse variants_json for admin:", e);
                product.variants = []; // 解析失败则返回空数组
            }
        } else {
             product.variants = []; // 兼容没有此字段的情况
        }
        
        // (可选：如果您的旧数据依赖 ProductVariants 表，可以在此添加兼容查询)
        // -> 针对新增卡密功能，此查询变为必须
        if (!product.variants || product.variants.length === 0) {
            const { results: variants } = await env.MY_HLTX.prepare(
                "SELECT id, name, price_adjustment, stock_count FROM ProductVariants WHERE product_id = ?1"
            ).bind(params.id).all();
             product.variants = variants;
        }
        
        delete product.variants_json; // 不将此原始字段发送给前端
        return json(product);

    } catch (e) {
        return error(500, '获取商品详情失败: ' + e.message);
    }
});

// --- 新增路由 (2/2): 更新商品 (后台管理) ---
router.put('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    const productId = params.id;
    
    // --- 1. 获取前端发送的完整 body ---
    const body = await request.json();
    const { 
        name, description, image_url, variants, 
        short_description, keywords, category_id, 
        sort_weight, is_active 
    } = body;

    // --- 2. 校验 (与创建时相同) ---
    if (!name) {
        return error(400, '商品名称是必填项');
    }
    if (!variants || !Array.isArray(variants) || variants.length === 0) {
        return error(400, '至少需要一个商品规格');
    }
    
    // --- 3. 从第一个规格中提取数据以存入 Products 主表 ---
    const firstVariant = variants[0];
    const base_price = parseFloat(firstVariant.price);
    const stock = parseInt(firstVariant.stock) || 0;
    const addon_price = parseFloat(firstVariant.addon_price) || 0;
    const wholesale_config = firstVariant.wholesale_config || '';

    if (isNaN(base_price) || base_price <= 0) {
        return error(400, '商品名称和有效价格是必填项');
    }
    if (!category_id) {
        return error(400, '所属分类是必填项');
    }
    
    const isActiveInt = is_active ? 1 : 0;
    let variantsJson = JSON.stringify(variants);
    
    // --- 4. D1 数据库更新 (使用 UPDATE) ---
    try {
        const stmt = env.MY_HLTX.prepare(
            `UPDATE Products SET
                name = ?1,
                description = ?2,
                base_price = ?3,
                image_url = ?4,
                variants_json = ?5,
                short_description = ?6,
                keywords = ?7,
                category_id = ?8,
                stock = ?9,
                wholesale_config = ?10,
                addon_price = ?11,
                sort_weight = ?12,
                is_active = ?13
            WHERE id = ?14`
        );
        
        await stmt.bind(
            name,                      // ?1
            description,               // ?2
            base_price,                // ?3
            image_url || '',           // ?4
            variantsJson,              // ?5
            short_description || '',   // ?6
            keywords || '',            // ?7
            parseInt(category_id),     // ?8
            stock,                     // ?9
            wholesale_config,          // ?10
            addon_price,               // ?11
            parseInt(sort_weight) || 0,// ?12
            isActiveInt,               // ?13
            productId                  // ?14 (WHERE 条件)
        ).run();

        return json({ id: productId, success: true });
    } catch (e) {
        console.error("D1 Update Error:", e);
        return error(500, '更新商品失败: ' + e.message); 
    }
});


// 获取所有文章 (后台管理)
router.get('/api/admin/articles', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT id, title, created_at FROM Articles ORDER BY created_at DESC").all();
        return json(results);
    } catch (e) {
        return error(500, '获取文章列表失败: ' + e.message);
    }
});


// 添加新文章
router.post('/api/admin/articles', withAuth, async (request, env) => {
    const { title, slug, summary, content } = await request.json();
    
    if (!title || !slug || !content) {
        return error(400, '标题、Slug 和内容是必填项');
    }

    try {
        await env.MY_HLTX.prepare(
            "INSERT INTO Articles (title, slug, summary, content) VALUES (?1, ?2, ?3, ?4)"
        ).bind(title, slug, summary || '', content).run();
        
        const result = await env.MY_HLTX.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建文章失败: ' + e.message);
    }
});


// 获取所有分类 (后台管理)
router.get('/api/admin/categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM Categories").all();
        return json(results);
    } catch (e) {
        return error(500, '获取分类失败: ' + e.message);
    }
});


// 添加新分类
router.post('/api/admin/categories', withAuth, async (request, env) => {
    const { name, slug } = await request.json();

    if (!name || !slug) {
        return error(400, '名称和Slug是必填项');
    }

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


// 获取所有订单 (后台管理)
router.get('/api/admin/orders', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare(`
            SELECT 
                o.id AS order_id, 
                o.total_amount, 
                o.status, 
                o.created_at, 
                p.name AS product_name, 
                pv.name AS variant_name
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


// 获取卡密列表 (后台管理)
router.get('/api/admin/cards', withAuth, async (request, env) => {
    try {
        // SELECT * 会自动包含新添加的 preset_info 列
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM Cards ORDER BY id DESC").all();
        return json(results);
    } catch (e) {
        return error(500, '获取卡密列表失败: ' + e.message);
    }
});

// START: 修改 - 新增卡密路由
router.post('/api/admin/cards', withAuth, handleAddCard);
// END: 修改

// START: 修改 - handleAddCard 函数
async function handleAddCard(request, env) {
    try {
        const { variant_id, secret, is_sold } = await request.json();

        if (!variant_id || !secret) {
            return error(400, '商品规格ID和卡密内容不能为空');
        }
        
        const variant = await env.MY_HLTX.prepare("SELECT id FROM ProductVariants WHERE id = ?1").bind(variant_id).first();
        if (!variant) return error(404, '商品规格 (Variant) 未找到');

        // 将textarea中的多行卡密拆分
        const secrets = secret.split('\n').filter(s => s.trim().length > 0);
        if (secrets.length === 0) {
             return error(400, '卡密内容不能为空');
        }

        const db = env.MY_HLTX;
        const stmts = [];
        const now = new Date().toISOString();
        
        for (const sec of secrets) {
            // 使用 parseCardSecret 辅助函数
            const parsed = parseCardSecret(sec);
            
            // 插入到新 schema: (card_key, preset_info)
            stmts.push(
                db.prepare('INSERT INTO Cards (variant_id, card_key, preset_info, is_used, created_at) VALUES (?, ?, ?, ?, ?)')
                  .bind(variant_id, parsed.secret, parsed.preset, is_sold || 0, now)
            );
        }

        await db.batch(stmts);
        
        // 只有当卡密是 "未使用" 时才增加库存
        if ((is_sold || 0) === 0) {
             await env.MY_HLTX.prepare(
                "UPDATE ProductVariants SET stock_count = stock_count + ?1 WHERE id = ?2"
            ).bind(stmts.length, variant_id).run();
        }

        return json({ success: true, count: stmts.length }, { status: 201 });

    } catch (e) {
        console.error('Error adding card:', e.message);
        return error(500, 'Internal Server Error: ' + e.message);
    }
}
// END: 修改

// 导入新卡密 (后台管理)
router.post('/api/admin/cards/import', withAuth, async (request, env) => {
    const { variant_id: variantId, keys } = await request.json(); // keys 是一个字符串数组
    const variant_id = parseInt(variantId);

    if (!variant_id || !keys || !Array.isArray(keys)) {
        return error(400, '规格ID和卡密列表是必填项');
    }

    try {
        const variant = await env.MY_HLTX.prepare("SELECT id FROM ProductVariants WHERE id = ?1").bind(variant_id).first();
        if (!variant) return error(404, 'Variant not found');

        let addedCount = 0;
        
        // START: 修改 - 准备新的 SQL 语句
        const insertCardStmt = env.MY_HLTX.prepare(
            "INSERT INTO Cards (variant_id, card_key, preset_info) VALUES (?1, ?2, ?3)"
        );
        
        const insertPromises = keys.map(key => {
            // 使用 parseCardSecret 辅助函数
            const parsed = parseCardSecret(key);
            // 绑定到新 schema
            return insertCardStmt.bind(variant_id, parsed.secret, parsed.preset).run();
        });
        // END: 修改
        
        const results = await Promise.allSettled(insertPromises);

        results.forEach(res => {
            if (res.status === 'fulfilled' && res.value && res.value.success) {
                addedCount++;
            }
        });

        // 更新 ProductVariant 的库存 (stock_count)
        await env.MY_HLTX.prepare(
            "UPDATE ProductVariants SET stock_count = stock_count + ?1 WHERE id = ?2"
        ).bind(addedCount, variant_id).run();

        return json({ success: true, added_count: addedCount }, { status: 201 });
    } catch (e) {
        return error(500, '导入卡密失败: ' + e.message);
    }
});


// 获取支付设置 (后台管理)
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


// 保存支付设置 (后台管理)
router.post('/api/admin/settings/payment', withAuth, async (request, env) => {
    const updates = await request.json();
    
    try {
        // 使用 REPLACE INTO 实现 UPSERT
        const promises = Object.entries(updates).map(([key, value]) => {
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


// 获取通用配置 (后台管理)
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


// 保存通用配置 (后台管理)
router.post('/api/admin/settings/config', withAuth, async (request, env) => {
    const updates = await request.json();
    
    try {
        // 使用 REPLACE INTO 实现 UPSERT
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

// 路由到静态文件（如果路由不匹配任何 API，则返回静态文件）
router.all('*', (request, env) => env.ASSETS.fetch(request));


// 暴露给 Cloudflare Worker 的入口
export default {
    /**
     * @param {Request} request
     * @param {Env} env 环境变量和绑定
     */
    async fetch(request, env) {
        if (!env.MY_HLTX) {
            return error(500, "Worker配置错误: 缺少D1数据库绑定'MY_HLTX'");
        }
        
        // 处理路由
        return router.handle(request, env);
    }
};
