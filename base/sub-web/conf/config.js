// 修改此文件即可调整静态部署的后端和模板，无须重新构建。
window.config = {
  siteName: 'Subweb',
  apiUrl: [
    { value: 'https://api.miaoceo.com', text: 'SubConverter-Extended', profile: 'extended' },
    { value: 'https://sub.miaoceo.com', text: 'subconverter', profile: 'standard' },
  ],
  shortUrl: 'https://i.miaoceo.com',
  // Extended 的 Clash / Mihomo 可选 Aethersailor 模板；false 可关闭内置模板。
  aethersailorPresets: true,
  remoteConfigOptions: [
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule_B.ini',
      text: 'LovinYarn · Clash',
      targets: ['clash', 'clashr'],
    },
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule_Stash.ini',
      text: 'LovinYarn · Stash',
      targets: ['stash'],
    },
    {
      value: 'https://raw.githubusercontent.com/xuanranran/Clash/main/Clash/ClashRule.ini',
      text: 'LovinYarn · Surge',
      targets: ['surge', 'surfboard'],
    },
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini',
      text: 'ACL4SSR · Online',
      targets: ['clash', 'clashr'],
    },
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini',
      text: 'ACL4SSR · Full',
      targets: ['clash', 'clashr'],
    },
    {
      value: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini',
      text: 'ACL4SSR · Mini',
      targets: ['clash', 'clashr'],
    },
  ],
};
