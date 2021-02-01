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
                text: '协议',
                link: '/standard/',
            },
        ],
        sidebar: {
            "/standard/": [
                // "/standard/",
                "/standard/http2",
                "/standard/websocket",
            ],
        }
    }
};
