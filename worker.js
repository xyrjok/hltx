import { Router, json } from 'itty-router';

// 创建一个新的路由
const router = Router();

// 定义一个测试 API 路由
router.get('/api/test', () => {
    return new Response('Hello from Cloudflare Worker!', {
        headers: { 'Content-Type': 'text/plain' },
    });
});

// 404 处理
router.all('*', () => new Response('Not Found', { status: 404 }));

// Worker 入口
export default {
    fetch: (request) =>
        router.handle(request),
};
