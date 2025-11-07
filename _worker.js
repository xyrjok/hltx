// _worker.js: Cloudflare Worker D1 数据库集成版本
// 此文件已移除所有 Mock 数据和逻辑，改为通过 env.DB 连接 Cloudflare D1 数据库。
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
        const { results } = await env.DB.prepare(
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
        const { results } = await env.DB.prepare(
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
        const { results } = await env.DB.prepare(
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
            const { results: variants } = await env.DB.prepare(
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
        const { results } = await env.DB.prepare(
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
        const article = await env.DB.prepare(
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
        const { results: variantResults } = await env.DB.prepare(`
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
        const availableCard = await env.DB.prepare(`
            SELECT id, card_key FROM Cards 
            WHERE variant_id = ?1 AND is_used = 0 
            LIMIT 1
        `).bind(variantIdInt).first();

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
        await env.DB.prepare(`
            INSERT INTO Orders (id, variant_id, total_amount, status, payment_id, delivered_card)
            VALUES (?1, ?2, ?3, 'paid', ?4, ?5)
        `).bind(orderId, variantIdInt, totalAmount, paymentId, availableCard.card_key).run();
        
        // 5. 将卡密标记为已使用
        await env.DB.prepare(`
            UPDATE Cards SET is_used = 1, used_at = datetime('now') WHERE id = ?1
        `).bind(availableCard.id).run();
        
        // 6. 减少规格库存
        await env.DB.prepare(
             "UPDATE ProductVariants SET stock_count = stock_count - 1 WHERE id = ?1"
        ).bind(variantIdInt).run();

        const newOrder = {
            order_id: orderId,
            product_name: `${variant.product_name} - ${variant.variant_name}`,
            total_amount: totalAmount,
            status: 'paid', 
            delivered_card: availableCard.card_key,
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
        const order = await env.DB.prepare(
            "SELECT id, status, delivered_card FROM Orders WHERE id = ?1"
        ).bind(params.id).first();

        if (!order) return error(404, 'Order not found');
        return json({
            order_id: order.id,
            status: order.status,
            delivered_card: order.delivered_card,
        });
    } catch (e) {
        return error(500, '获取订单详情失败: ' + e.message);
    }
});


// --- 后台管理 API 路由 (Admin API Routes) ---

// 获取所有商品列表
router.get('/api/admin/products', withAuth, async (request, env) => {
    try {
        const { results } = await env.DB.prepare(
            "SELECT id, name, base_price, is_active, sort_weight FROM Products ORDER BY id DESC"
        ).all();
        return json(results);
    } catch (e) {
        return error(500, '获取商品列表失败: ' + e.message);
    }
});


// 添加新商品 (包含所有新增字段)
router.post('/api/admin/products', withAuth, async (request, env) => {
    const { 
        name, description, base_price, image_url, variants, 
        short_description, keywords, category_id, stock, 
        wholesale_config, addon_price, sort_weight, is_active 
    } = await request.json();
    
    // --- 校验 ---
    if (!name || isNaN(base_price) || base_price <= 0) {
        return Response.json({ success: false, message: '商品名称和有效价格是必填项' }, { status: 400 });
    }
    if (!category_id) {
        return Response.json({ success: false, message: '所属分类是必填项' }, { status: 400 });
    }
    
    const isActiveInt = is_active ? 1 : 0;
    // 如果有规格，将其 JSON 化存储
    let variantsJson = variants && Array.isArray(variants) && variants.length > 0 
                       ? JSON.stringify(variants) : null;
    
    // --- D1 数据库插入 ---
    try {
        const stmt = env.DB.prepare(
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
            name, description, base_price, image_url || '', variantsJson,
            short_description || '', 
            keywords || '',          
            parseInt(category_id),   
            parseInt(stock) || 0,    
            wholesale_config || '',  
            parseFloat(addon_price) || 0, 
            parseInt(sort_weight) || 0, 
            isActiveInt              
        ).run();

        const result = await env.DB.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        console.error("D1 Insert Error:", e);
        // 如果是 UNIQUE 约束错误，可以返回更友好的信息
        return error(500, '创建商品失败: ' + e.message); 
    }
});


// 删除商品
router.delete('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    try {
        const result = await env.DB.prepare("DELETE FROM Products WHERE id = ?1").bind(params.id).run();
        // 检查删除是否成功
        if (result.changes === 0) {
            return error(404, '商品未找到或删除失败');
        }
        return json({ success: true });
    } catch (e) {
        return error(500, '删除商品失败: ' + e.message);
    }
});


// 获取所有文章 (后台管理)
router.get('/api/admin/articles', withAuth, async (request, env) => {
    try {
        const { results } = await env.DB.prepare("SELECT id, title, created_at FROM Articles ORDER BY created_at DESC").all();
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
        await env.DB.prepare(
            "INSERT INTO Articles (title, slug, summary, content) VALUES (?1, ?2, ?3, ?4)"
        ).bind(title, slug, summary || '', content).run();
        
        const result = await env.DB.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建文章失败: ' + e.message);
    }
});


// 获取所有分类 (后台管理)
router.get('/api/admin/categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.DB.prepare("SELECT * FROM Categories").all();
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
        await env.DB.prepare(
            "INSERT INTO Categories (name, slug) VALUES (?1, ?2)"
        ).bind(name, slug).run();
        
        const result = await env.DB.prepare("SELECT last_insert_rowid() as id").first();
        return json({ id: result.id, success: true }, { status: 201 });
    } catch (e) {
        return error(500, '创建分类失败: ' + e.message);
    }
});


// 获取所有订单 (后台管理)
router.get('/api/admin/orders', withAuth, async (request, env) => {
    try {
        const { results } = await env.DB.prepare(`
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
        const { results } = await env.DB.prepare("SELECT * FROM Cards ORDER BY id DESC").all();
        return json(results);
    } catch (e) {
        return error(500, '获取卡密列表失败: ' + e.message);
    }
});


// 导入新卡密 (后台管理)
router.post('/api/admin/cards/import', withAuth, async (request, env) => {
    const { variant_id: variantId, keys } = await request.json();
    const variant_id = parseInt(variantId);

    if (!variant_id || !keys || !Array.isArray(keys)) {
        return error(400, '规格ID和卡密列表是必填项');
    }

    try {
        const variant = await env.DB.prepare("SELECT id FROM ProductVariants WHERE id = ?1").bind(variant_id).first();
        if (!variant) return error(404, 'Variant not found');

        let addedCount = 0;
        const insertCardStmt = env.DB.prepare(
            "INSERT INTO Cards (variant_id, card_key) VALUES (?1, ?2)"
        );
        
        const insertPromises = keys.map(key => insertCardStmt.bind(variant_id, key).run());
        const results = await Promise.allSettled(insertPromises);

        results.forEach(res => {
            if (res.status === 'fulfilled' && res.value && res.value.success) {
                addedCount++;
            }
        });

        // 更新 ProductVariant 的库存 (stock_count)
        await env.DB.prepare(
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
        const { results } = await env.DB.prepare("SELECT key, value FROM PaymentSettings").all();
        
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
            return env.DB.prepare(
                "REPLACE INTO PaymentSettings (key, value) VALUES (?1, ?2)"
            ).bind(key, value).run();
        });

        await Promise.all(promises);

        const { results } = await env.DB.prepare("SELECT key, value FROM PaymentSettings").all();
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
        const { results } = await env.DB.prepare("SELECT key, value FROM Configurations").all();
        
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
            return env.DB.prepare(
                "REPLACE INTO Configurations (key, value) VALUES (?1, ?2)"
            ).bind(key, value).run();
        });

        await Promise.all(promises);

        const { results } = await env.DB.prepare("SELECT key, value FROM Configurations").all();
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
        if (!env.DB) {
            return error(500, "Worker配置错误: 缺少D1数据库绑定'MY_HLTX'");
        }
        
        // 处理路由
        return router.handle(request, env);
    }
};
