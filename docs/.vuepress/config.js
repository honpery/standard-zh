module.exports = {
    title: 'Standard Zh',
    description: '规范翻译',
    base: '/standard-zh/',
    themeConfig: {
        repo: 'honpery/standard-zh',
        sidebarDepth: 4,
        displayAllHeaders: true,
        lastUpdated: 'Last Updated',
        nav: [
            {
                text: '网络协议',
                link: '/standard/',
                items: [
                    { text: 'HTTP 2', link: '/standard/http2/' },
                    { text: 'WebSocket', link: '/standard/websocket/' }
                ]
            },
        ],
        sidebar: 'auto',
        collapsable: true,
    }
};
