window.config = {
  // 网站标题
  siteName: 'Subconverter Web',
  // API 地址
  apiUrl: [
    {
      value: 'http://localhost:25500',
      text: '本地版 局域网请修改localhost',
    },
    {
      value: 'https://sub.miaoco.me',
      text: 'LovinYarn 后端',
    }
  ],
  // 短域名服务地址
  shortUrl: 'https://i.miaoco.me',
  // 首页菜单
  menuItem: [
    {
      title: '首页',
      link: '/',
      target: '',
    },
    {
      title: 'GitHub',
      link: 'https://github.com/xuanranran/subweb',
      target: '_blank',
    },
  ],
  // 远程配置地址
  remoteConfigOptions: [
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule_B.ini',
      text: 'LovinYarn Online Clash',
    },
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule_Stash.ini',
      text: 'LovinYarn Online Stash',
    },
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule.ini',
      text: 'LovinYarn Online Surge',
    },
    // ACL4SSR Options
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini',
      text: 'ACL4SSR Online',
    },
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini',
      text: 'ACL4SSR Online Full',
    },
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini',
      text: 'ACL4SSR Online Mini',
    },
    // Universal Options
    {
      value: 'https://raw.githubusercontent.com/cnsilvan/sub-web-config/main/config/uncensored.ini',
      text: 'Uncensored Config',
    }
  ],
};
