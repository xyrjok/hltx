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

// 创建订单
router.post('/api/orders', async (request, env) => {
    const { variant_id, custom_info } = await request.json();
    const variantIdInt = parseInt(variant_id);

    if (isNaN(variantIdInt)) return error(400, 'Invalid variant ID');

    try {
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

        const totalAmount = variant.base_price + variant.price_adjustment + (variant.addon_price || 0);
        const orderId = `D1-${Date.now()}`;
        const paymentId = `PAY-${Date.now()}`;

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


// 删除商品
router.delete('/api/admin/products/:id', withAuth, async ({ params }, env) => {
    const db = env.MY_HLTX;
    try {
        await db.prepare("DELETE FROM Products WHERE id = ?1").bind(params.id).run();
        return json({ success: true });
    } catch (e) {
        return error(500, '删除商品失败: ' + e.message);
    }
});

// 获取单个商品详情 (后台管理)
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

// 更新商品 (后台管理)
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


// --- 其他 Admin API ---

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
// (添加) 获取单篇文章 (用于编辑)
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

// (添加) 更新文章
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

// (添加) 删除文章 (供 articles.html 页面使用)
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

// --- 结束更新文章 ---

router.get('/api/admin/categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM Categories").all();
        return json(results);
    } catch (e) {
        return error(500, '获取分类失败: ' + e.message);
    }
});


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
// --- 从这里开始添加 (文章分类 API) ---

router.get('/api/admin/article_categories', withAuth, async (request, env) => {
    try {
        const { results } = await env.MY_HLTX.prepare("SELECT * FROM ArticleCategories").all();
        return json(results);
    } catch (e) {
        return error(500, '获取文章分类失败: ' + e.message);
    }
});

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
// (添加) 删除文章分类
router.delete('/api/admin/article_categories/:id', withAuth, async ({ params }, env) => {
    try {
        // 检查 Articles 表中是否还有文章在使用此分类ID
        const usage = await env.MY_HLTX.prepare(
            "SELECT id FROM Articles WHERE article_category_id = ?1 LIMIT 1"
        ).bind(params.id).first();

        if (usage) {
            return error(400, '删除失败：仍有文章在使用此分类，请先移除或修改相关文章。');
        }

        // 如果没有文章使用，则执行删除
        await env.MY_HLTX.prepare(
            "DELETE FROM ArticleCategories WHERE id = ?1"
        ).bind(params.id).run();
        
        return json({ success: true });
    } catch (e) {
        return error(500, '删除文章分类失败: ' + e.message);
    }
});
// --- 添加删除文章分类结束 ---

// --- 添加 (文章分类 API)到这里结束 ---

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

// 卡密管理 API
// START: 关键修改 - 修复 /api/admin/cards API
router.get('/api/admin/cards', withAuth, async (request, env) => {
    try {
        // (!!!) 关键修复: 使用 JOIN 获取真实的商品和规格名称
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
// END: 关键修改

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

// 设置 API
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

router.post('/api/admin/settings/payment', withAuth, async (request, env) => {
    const updates = await request.json();
    try {
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
