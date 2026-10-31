use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;

pub const DEFAULT_HOME_ONION: &str = "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion";

pub const BOOTSTRAP_SEEDS: &[&str] = &[
    "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion",
    "kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion",
    "zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion",
    "e3a7jfpzcsj6e7o7lzrwos2qz53wesp62lgjmsa3pld6xwnqvromrvqd.onion",
    "xememocnagky3qlkkx7n6tgkmjrzhmfzoahbke3gvtea6nu4nnc27sad.onion",
    "7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion",
    "jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion",
    "4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion",
    "nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion",
    "hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion",
    "gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion",
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
    "wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion",
    "o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion",
    "5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion",
    "o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion",
    "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion",
    "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion",
    "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion",
    "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion",
    "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion",
    "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion",
    "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion",
    "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion",
    "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion",
    "rbgms6kvlga2kxrxr4pyyjqkjlfjd2vu75tga2snp5elnp7knimm3uad.onion",
    "l7enqvulavxihx2bpvkqqctqkaqlzp4ymn43cfxpvjqyjmq4svxheoid.onion",
    "paexh3f2grmh4tlux4ctswlnozdeg3vgcpvgtzmyjvvttpjsgn6cwxqd.onion",
    "bvtojfof2nzay5u4kqag4e5nxfyuexwx4wyv66eopczwzq4h2ftj5qad.onion",
    "cgsl5koa6m5cwd2e7bh6yygj6q2rfvrt6jmt3nggk4ht7z7v3ssypeid.onion",
    "bd5xv3bopftiyak43nuzsurgl4wwrlit37ngrgdtm5hzdcyvpbop7kqd.onion",
    "7rxpged4h4uoony6rj4j56cw3exmjzmf2k6ylw6pyn4wk6eimiw6asad.onion",
    "ichzjrvw4r6cedpixxws2nfltppzesfj42jqw75nilnpdui3ybgou7ad.onion",
    "xzl3whmw7bzap5itmierivv7p4pleynvrhbbqvszsiyzzphlkjjx2pad.onion",
];

pub const DEPRECATED_SEEDS: &[&str] = &[
    "rbgms6kvdr4i4657d5s74ld7m576sbl4fksffmff5k4ebm3zbpffv4id.onion",
    "l7enqvulm34d6v3t3f2e3b4u224l6v4x7x2q3c5k6r7p2v4n6m4x5zad.onion",
    "paexh3f2v4j6n7m2k5l8p3q6r9s2t5v8w3x6y9z2b5c8d3f6g9h2j5id.onion",
    "bvtojfofv6m2n5p8q3r6s9t2v5w8x3y6z9b2c5d8f3g6h9j2k5l8m3ad.onion",
    "cgsl5koav8p3q6r9s2t5v8w3x6y9z2b5c8d3f6g9h2j5k8l3m6n9p2id.onion",
    "bd5xv3bon2v5w8x3y6z9b2c5d8f3g6h9j2k5l8m3n6p9q2r5s8t3v6ad.onion",
    "7rxpged4z3b6c9d2f5g8h3j6k9l2m5n8p3q6r9s2t5v8w3x6y9z2b5id.onion",
    "kn4u2ef3y7ecyvbh36fkezxbbjrkc67ddtsf7m2dyrcpfdba7t2c5jad.onion",
    "zqdx5vye5tnc2b5ffj3ufc255wucx2z3b2bfvnefdn3g2ef5z2x67nad.onion",
    "dkkwnbju5xxhd5rrdg7sbxmh5fyoh7loew6mpaxb5xjjckimk6rt63ad.onion",
    "e62b43tij6ijd7krxqjmt2xhm6omfcll34or22sqo4fhpkykoaza6cad.onion",
    "azw5qxf4jnfudeei3nanggojle62g4duoxtxjj2pjuvm42xb3456vjad.onion",
    "dr73uzslasuijogigjnvdws4yoajqnhw6yjyvufq3nobm6xibntnwzqd.onion",
    "puqjsmsyyzmxjdtcgr2fl4wrdazqd2phaqrz26alzwyletbvekkxhyyd.onion",
    "ch4s5llfqshxbvba2yulgp5kbopq25w3qqrtli67sle6smbujlebn2id.onion",
    "2qgcxodv7oskwadopetbf563vh3ylxrmbeemqf7wvfkqkgzfk7omibid.onion",
    "5wniyn4yavtrfirlpdbqog2trucx7l2mo46xhzmmsqv2gukgiz6a62ad.onion",
    "b2okgesv7hmaklzn52ampqndxmvqw6mue242jnzacfrqlhvy7qtnjoyd.onion",
    "gsjapr6lwyifkzygymzewk7qcpd5smeqtqxwffwtcmtvwzktojirczqd.onion",
    "mmhzcbaq5td2gsoexzxaix7wajrexfc7vwhpdeavmly7mp4iog7kgryd.onion",
    "uabdscyj2a25yjdggf7p6fjwj66vfbntsbi3mmkqz5letlve5atyc7qd.onion",
    "2rapl6ti6jepxidbq6krbvtv32h257sb3tyhamjd3n4lx36c76uhdnid.onion",
    "cstl5a24l3sj7vlpjmu3udhatyibzazqdtz3ljxeug5svoibmzno3dad.onion",
    "dp7kur7f5vjn5mfnrkxgtelqmr4i5d62nzmmqrnrzdndakkembx7sjyd.onion",
    "izin6p6lln6gtmppzi57fwepnzjesr63e6ws5ox36ncsqu4bzbcjwsid.onion",
    "mwlkugl2uejlwl44tbrhe35chzbxx453r5iwnv5hr2hvtzphjttbypid.onion",
    "j3jctr732xjkkkcjkoysgqlktlomr3zexhiv4asvvmdomjoo26lwidyd.onion",
    "rk6qrjwlte4veuximrnpgkmiqrbcxpj3i2h3p2f7urr35pjpvw5pz4id.onion",
    "ucbbmzi4h4zu2yd4l73r52jzvmq7cvzgwcatqmwdcnoq4hjose3n42id.onion",
];

pub const LEGACY_V1_PEERS: &[&str] = &[
    "e62b43tij6ijd7krxqjmt2xhm6omfcll34or22sqo4fhpkykoaza6cad.onion",
];

pub const DORMANT_SEEDS: &[&str] = &[
    "azw5qxf4jnfudeei3nanggojle62g4duoxtxjj2pjuvm42xb3456vjad.onion",
    "dr73uzslasuijogigjnvdws4yoajqnhw6yjyvufq3nobm6xibntnwzqd.onion",
];

pub const COLOCATED_PVE_HS_PEERS: &[&str] = &[
    "7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion",
    "4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion",
    "nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion",
    "hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion",
    "gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion",
    "o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion",
    "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion",
    "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion",
    "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion",
    "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion",
    "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion",
    "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion",
    "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion",
    "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion",
    "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion",
];

pub const COLOCATED_USEAST_8082_PEERS: &[&str] = &[
    "wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion",
    "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
    "5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion",
    "o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoMeta {
    pub node_name: String,
    pub map_label: String,
    pub location: String,
    pub provider: String,
    pub lat: f64,
    pub lon: f64,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeGeoDetail {
    pub domain: String,
    pub node_name: String,
    pub map_label: String,
    pub location: String,
    pub provider: String,
    pub lat: f64,
    pub lon: f64,
    pub role: String,
    pub status: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub protocol_version: u8,
    pub auto_discovered: u8,
    pub health_score: u8,
    pub rtt_ms: f64,
    pub last_seen_sec: i64,
    pub fail_count: u32,
}

pub fn static_node_geo_map() -> &'static HashMap<&'static str, GeoMeta> {
    static MAP: OnceLock<HashMap<&'static str, GeoMeta>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        let entries = [
            (
                "onion4zr3bsdeaelksemwokl5qmxd5o7jyblf46vc2mfl6cozgw77tqd.onion",
                "👑 Nó 1 — Mesh Node #1 (BR-SP)",
                "N1•SP",
                "São Paulo, Brasil",
                "OnionTalk Sovereign Mesh (BR-SP #1)",
                -15.5,
                -47.5,
                "👑 Seed Node (Master)",
            ),
            (
                "kn4u2xxl2otoo2ujv3mhehwfwbw7mtppaf56fu3nxogvv7eekf2qdrid.onion",
                "🖥️ Nó 2 — Mesh Node #2 (BR-SP)",
                "N2•SP",
                "São Paulo, Brasil",
                "OnionTalk Sovereign Mesh (BR-SP #2)",
                -23.0,
                -45.5,
                "🖥️ Sovereign Relay (BR-SP #2)",
            ),
            (
                "e3a7jfpzcsj6e7o7lzrwos2qz53wesp62lgjmsa3pld6xwnqvromrvqd.onion",
                "☁️ Nó 3 — Mesh Node #3 (US-East)",
                "N3•EKS",
                "US-East #1, EUA",
                "OnionTalk Sovereign Mesh (US-East #1)",
                49.0,
                -74.0,
                "☁️ Cloud Relay (US-East #1)",
            ),
            (
                "zqdx5x7pfybox7m5rz3fe5kiouxhipvh3ekuteq2urrrvwcxjttnmgid.onion",
                "🟧 Nó 4 — Mesh Node #4 (BR-SP)",
                "N4•OCI",
                "São Paulo, Brasil",
                "OnionTalk Sovereign Mesh (BR-SP #3)",
                -30.5,
                -51.0,
                "🟧 Cloud Relay (BR-SP #3)",
            ),
            (
                "xememocnagky3qlkkx7n6tgkmjrzhmfzoahbke3gvtea6nu4nnc27sad.onion",
                "☁️ Nó 5 — US-East Sovereign #2",
                "N5•VA",
                "Ashburn, Virginia, EUA (us-east-1)",
                "OnionTalk Sovereign Cloud (US-East #2)",
                26.5,
                -76.0,
                "☁️ Cloud Relay (US-East #2)",
            ),
            (
                "7bntuiegd3stvcylvx7rhnhq7ncasxiokunbf5onvvm34dg5gccvooid.onion",
                "🇫🇷 Nó 6 — Mesh Node #6 (EU-West)",
                "N6•PAR1",
                "Paris, França (EU-West)",
                "OnionTalk Sovereign Mesh (EU-West #1)",
                54.0,
                -4.0,
                "🇫🇷 Cloud Relay (Paris, FR)",
            ),
            (
                "jz6urt6ckkqqvtasm6bll2mryhksjcawcl4tbguif5nqvxgsfsx6ywad.onion",
                "🌐 Nó 7 — Mesh Node #7 (US-East)",
                "N7•US3",
                "US-East, EUA",
                "OnionTalk Sovereign Mesh (US-East #3)",
                26.5,
                -100.0,
                "🌐 Cloud Relay (US-East #3)",
            ),
            (
                "4wufywh2k6ayyz6nmh2w25hj5vjsqgkve24o2tthvc7rhyvxnhaghqqd.onion",
                "⚡ Nó 8 — Mesh Node #8 (US-Central)",
                "N8•OH1",
                "Columbus, Ohio, EUA (us-east)",
                "OnionTalk Sovereign Mesh (US-Central #1)",
                41.5,
                -75.0,
                "⚡ Cloud Relay (US-Central #1)",
            ),
            (
                "nwsoa6ddtbbqbwcceanhhj3j23d5a47zbpbs6zspz5zoeytzqpzvkqqd.onion",
                "🇷🇺 Nó 9 — Mesh Node #9 (EE-East)",
                "N9•MSK1",
                "Moscou, Rússia (msk1)",
                "OnionTalk Sovereign Mesh (EE-East #1)",
                54.0,
                40.0,
                "🇷🇺 Cloud Relay (Moscou, RU)",
            ),
            (
                "bk7iegv3v232ycjyf5ylwsdx42iozvy2dhhff5zn3ciwa3g2lkifdlad.onion",
                "🐳 Nó 10 — US-East Container Relay",
                "N10•B4A1",
                "US-East (US-East Container Mesh #1), EUA",
                "OnionTalk Container Mesh (US-East #5)",
                41.5,
                -98.0,
                "🐳 Cloud Relay (US-East Container Node #1)",
            ),
            (
                "hdjp7uaj4qemlmwtev7xmj2w3uexnv6ctplfgvbmpqxenbfgwjjwtrid.onion",
                "🇫🇷 Nó 11 — Mesh Node #11 (EU-West)",
                "N11•PAR2",
                "Paris, França (EU-West #2)",
                "OnionTalk Sovereign Mesh (EU-West #2)",
                46.5,
                -5.0,
                "🇫🇷 Cloud Relay (Paris #2, FR)",
            ),
            (
                "gcvfh67zltoyvithw6luetsrcec6cw42upzrsprxfmx27cvh7vidw4yd.onion",
                "🇫🇷 Nó 12 — Mesh Node #12 (EU-West)",
                "N12•PAR3",
                "Paris, França (EU-West #3)",
                "OnionTalk Sovereign Mesh (EU-West #3)",
                39.0,
                -6.0,
                "🇫🇷 Cloud Relay (Paris #3, FR)",
            ),
            (
                "wfi3nwuzk2tgrsf2scdy4nb6x6rtiocit4n26477zdlvdvshkgip3ayd.onion",
                "🟦 Nó 13 — US-Central Sovereign #1",
                "N13•NF",
                "Council Bluffs, Iowa, EUA (US-Central)",
                "OnionTalk Sovereign Cloud (US-Central)",
                49.0,
                -97.0,
                "🟦 Cloud Relay (US-Central)",
            ),
            (
                "5s6w6556f2eov2p6wlsuavaxh7si2kaswjwi5reojnovbzemducjzjqd.onion",
                "🇯🇵 Nó 14 — Global Mesh Node",
                "N14•JP",
                "Osaka, Japão (AP-Northeast)",
                "OnionTalk Sovereign Mesh (AP-East #1)",
                36.5,
                138.0,
                "🇯🇵 Cloud Relay (Osaka, JP)",
            ),
            (
                "o5yf3eukrwpt2g6jfo4q2y23xtuhoso2qknmnn6ac5eng5t4yt36roqd.onion",
                "🇸🇬 Nó 15 — Mesh Node #15 (AP-South)",
                "N15•SG",
                "Singapura (AP-Southeast)",
                "OnionTalk Sovereign Mesh (AP-South #1)",
                2.0,
                103.8,
                "🇸🇬 Cloud Relay (Singapura, SG)",
            ),
            (
                "o5zqqfl5znzexdojfnxgub5jnjelxdahbyxasjp57sx6fbxtjeqovpad.onion",
                "🇩🇪 Nó 16 — Mesh Node #16 (EU-Central)",
                "N16•DE",
                "Nuremberg, Alemanha (EU-Central)",
                "OnionTalk Sovereign Mesh (EU-Central #1)",
                50.0,
                15.0,
                "🇩🇪 Cloud Relay (Nuremberg, DE)",
            ),
            (
                "2amizuhb3p5x2lk3sra7f7thm5tgs7qtnysgowqpmexcqi4cuwyv7vad.onion",
                "🇨🇳 Nó 17 — AP-East Mesh (China)",
                "N17•CN",
                "Hangzhou, China (CN-East)",
                "OnionTalk AP-East Sovereign Mesh (CN)",
                29.0,
                117.5,
                "🇨🇳 Cloud Relay (Hangzhou, CN)",
            ),
            (
                "fllhsqmq2qj4stn22bvdtdigthj5bftq6bq6eb62ynk4kva4kfkbjtid.onion",
                "🐳 Nó 18 — Mesh Node #18 (US-East)",
                "N18•B4A2",
                "US-East (US-East Container Mesh #2), EUA",
                "OnionTalk Sovereign Mesh (US-East #5)",
                34.0,
                -99.0,
                "🐳 Cloud Relay (US-East #5)",
            ),
            (
                "rx46t5jwyoi7pqajaazk7xndqy6ep2n3x2u6bn7t3r34mg6eiehpdlad.onion",
                "⚡ Nó 19 — Mesh Node #19 (US-Central)",
                "N19•OH2",
                "Columbus, Ohio, EUA (us-east #2)",
                "OnionTalk Sovereign Mesh (US-Central #3)",
                34.0,
                -75.5,
                "⚡ Cloud Relay (US-Central #3)",
            ),
            (
                "q75gf2rwco7v33kuhmilafbtsvoxrygqmef7lq6allnk27zxruwzeqqd.onion",
                "🇷🇺 Nó 20 — Mesh Node #20 (EE-East)",
                "N20•MSK2",
                "Moscou, Rússia (msk1 #2)",
                "OnionTalk Sovereign Mesh (EE-East #2)",
                61.5,
                38.0,
                "🇷🇺 Cloud Relay (Moscou #2, RU)",
            ),
            (
                "huf4fjrdr67c3vir6b33s2rsspnmejgtn5azs2jby7yvfqwlsnxeawad.onion",
                "🟣 Nó 21 — US-East Mesh Relay #1",
                "N21•CH1",
                "Virginia / US-East #1, EUA (e1-us-east-azure)",
                "Sovereign Cloud Container #1",
                55.0,
                -122.0,
                "🟣 Cloud Relay (US-East #1)",
            ),
            (
                "ktr4uxdwjem2gabgwmivlx2uyyea6kdajpyb4fxxxa7x3zs5lq4fcyad.onion",
                "🟣 Nó 22 — US-East Mesh Relay #2",
                "N22•CH2",
                "Virginia / US-East #2, EUA (e1-us-east-azure)",
                "Sovereign Cloud Container #2",
                47.5,
                -123.0,
                "🟣 Cloud Relay (US-East #2)",
            ),
            (
                "6pq6ifyhhemh2pujbnr2i56mod6d7kpeu7s57i4syvxhdrltcztowtad.onion",
                "🟣 Nó 23 — US-East Mesh Relay #3",
                "N23•CH3",
                "Virginia / US-East #3, EUA (e1-us-east-azure)",
                "Sovereign Cloud Container #3",
                40.0,
                -123.0,
                "🟣 Cloud Relay (US-East #3)",
            ),
            (
                "kr2aex6umihb5bcdspc2q4npasng7zoee4i6ixx3qxgwcegscibis6id.onion",
                "🟣 Nó 24 — US-East Mesh Relay #4",
                "N24•CH4",
                "Virginia / US-East #4, EUA (e1-us-east-azure)",
                "Sovereign Cloud Container #4",
                32.5,
                -120.0,
                "🟣 Cloud Relay (US-East #4)",
            ),
            (
                "wzhsoh6ovtwvl7uthirgvpfry5zxo3bwm3rttsmmj2rkvgl7gbqkyaid.onion",
                "🟣 Nó 25 — US-East Mesh Relay #5",
                "N25•CH5",
                "Virginia / US-East #5, EUA (e1-us-east-azure)",
                "Sovereign Cloud Container #5",
                25.0,
                -114.0,
                "🟣 Cloud Relay (US-East #5)",
            ),
            (
                "4nz52tmtrs4p5dgzwaukx2vin6ugvo3stck3wax7gom63fbfcaairlad.onion",
                "📱 Nó 26 — Relay Mobile Zero-Leak (Android)",
                "N26•MOB",
                "Tor Hidden Service v3 (Anônimo / Zero-Leak)",
                "OnionTalk RelayNode Android v1.0.1",
                -12.5,
                -56.0,
                "📱 Mobile Pocket Relay (Zero-Leak)",
            ),
            (
                "rbgms6kvlga2kxrxr4pyyjqkjlfjd2vu75tga2snp5elnp7knimm3uad.onion",
                "🟧 Nó 27 — Mesh Node #27 (BR-SP)",
                "N27•OCI2",
                "São Paulo, Brasil (sa-saopaulo-1)",
                "OnionTalk Sovereign Mesh (BR-SP #4)",
                -23.55,
                -46.63,
                "🟧 Cloud Relay (BR-SP #4)",
            ),
            (
                "l7enqvulavxihx2bpvkqqctqkaqlzp4ymn43cfxpvjqyjmq4svxheoid.onion",
                "🟧 Nó 28 — Mesh Node #28 (BR-SP)",
                "N28•OCI3",
                "São Paulo, Brasil (sa-saopaulo-1 #2)",
                "OnionTalk Sovereign Mesh (BR-SP #5)",
                -23.62,
                -46.70,
                "🟧 Cloud Relay (BR-SP #5)",
            ),
            (
                "paexh3f2grmh4tlux4ctswlnozdeg3vgcpvgtzmyjvvttpjsgn6cwxqd.onion",
                "🟧 Nó 29 — Mesh Node #29 (BR-SP)",
                "N29•OCI4",
                "São Paulo, Brasil (sa-saopaulo-1 #3)",
                "OnionTalk Sovereign Mesh (BR-SP #6)",
                -23.48,
                -46.55,
                "🟧 Cloud Relay (BR-SP #6)",
            ),
            (
                "bvtojfof2nzay5u4kqag4e5nxfyuexwx4wyv66eopczwzq4h2ftj5qad.onion",
                "🟧 Nó 30 — Mesh Node #30 (BR-VCP)",
                "N30•VCP1",
                "Vinhedo, SP, Brasil (sa-vinhedo-1)",
                "OnionTalk Sovereign Mesh (BR-VCP #1)",
                -23.03,
                -46.97,
                "🟧 Cloud Relay (BR-VCP #1)",
            ),
            (
                "cgsl5koa6m5cwd2e7bh6yygj6q2rfvrt6jmt3nggk4ht7z7v3ssypeid.onion",
                "🟧 Nó 31 — Mesh Node #31 (BR-VCP)",
                "N31•VCP2",
                "Vinhedo, SP, Brasil (sa-vinhedo-1 #2)",
                "OnionTalk Sovereign Mesh (BR-VCP #2)",
                -22.90,
                -47.06,
                "🟧 Cloud Relay (BR-VCP #2)",
            ),
            (
                "bd5xv3bopftiyak43nuzsurgl4wwrlit37ngrgdtm5hzdcyvpbop7kqd.onion",
                "🟧 Nó 32 — Mesh Node #32 (BR-VCP)",
                "N32•VCP3",
                "Vinhedo, SP, Brasil (sa-vinhedo-1 #3)",
                "OnionTalk Sovereign Mesh (BR-VCP #3)",
                -23.18,
                -46.88,
                "🟧 Cloud Relay (BR-VCP #3)",
            ),
            (
                "7rxpged4h4uoony6rj4j56cw3exmjzmf2k6ylw6pyn4wk6eimiw6asad.onion",
                "🟧 Nó 33 — Mesh Node #33 (BR-VCP)",
                "N33•VCP4",
                "Vinhedo, SP, Brasil (sa-vinhedo-1 #4)",
                "OnionTalk Sovereign Mesh (BR-VCP #4)",
                -23.30,
                -47.13,
                "🟧 Cloud Relay (BR-VCP #4)",
            ),
            (
                "ichzjrvw4r6cedpixxws2nfltppzesfj42jqw75nilnpdui3ybgou7ad.onion",
                "🇧🇷 Nó 34 — Mesh Node #34 (BR-SP GCP)",
                "N34•GCP-BR",
                "Osasco, SP, Brasil (southamerica-east1)",
                "OnionTalk Sovereign Cloud (BR-SP GCP)",
                -23.53,
                -46.79,
                "🇧🇷 Cloud Relay (BR-SP GCP)",
            ),
            (
                "xzl3whmw7bzap5itmierivv7p4pleynvrhbbqvszsiyzzphlkjjx2pad.onion",
                "🇩🇪 Nó 35 — Mesh Node #35 (EU-Central GCP)",
                "N35•GCP-DE",
                "Frankfurt, Alemanha (europe-west3)",
                "OnionTalk Sovereign Cloud (EU-Central GCP)",
                50.11,
                8.68,
                "🇩🇪 Cloud Relay (Frankfurt, DE)",
            ),
        ];
        for (dom, name, label, loc, prov, lat, lon, role) in entries {
            m.insert(
                dom,
                GeoMeta {
                    node_name: name.to_string(),
                    map_label: label.to_string(),
                    location: loc.to_string(),
                    provider: prov.to_string(),
                    lat,
                    lon,
                    role: role.to_string(),
                },
            );
        }
        m
    })
}

pub fn build_node_geo_detail(
    domain: &str,
    is_local: bool,
    custom_geo: Option<GeoMeta>,
    online_state: Option<String>,
    rtt_ewma: f64,
    last_ok_epoch: Option<i64>,
    fail_count: u32,
    now_epoch_sec: i64,
) -> NodeGeoDetail {
    let static_map = static_node_geo_map();
    let auto_discovered = if static_map.contains_key(domain) { 0 } else { 1 };
    let meta = static_map
        .get(domain)
        .cloned()
        .or(custom_geo)
        .unwrap_or_else(|| {
            let hubs: &[(f64, f64)] = &[
                (47.37, 8.54),
                (59.33, 18.06),
                (52.23, 21.01),
                (40.42, -3.70),
                (64.14, -21.94),
                (4.71, -74.07),
                (-33.45, -70.66),
                (-26.20, 28.04),
                (37.56, 126.97),
                (-33.86, 151.20),
                (19.07, 72.87),
                (60.17, 24.94),
            ];
            let digest = Sha256::digest(domain.as_bytes());
            let h = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize;
            let (base_lat, base_lon) = hubs[h % hubs.len()];
            let fallback_lat = ((base_lat + (((h >> 8) % 10) as f64 - 5.0) * 0.15) * 10000.0).round() / 10000.0;
            let fallback_lon = ((base_lon + (((h >> 16) % 10) as f64 - 5.0) * 0.15) * 10000.0).round() / 10000.0;
            let short8: String = domain.chars().take(8).collect();
            let short4: String = domain.chars().take(4).collect();
            GeoMeta {
                node_name: format!("🛰️ Nó Auto-Join ({}...)", short8),
                map_label: format!("AUTO•{}", short4),
                location: "Tor Hidden Service v3 (Localização Oculta / Auto-Join)".to_string(),
                provider: "Tor v3 Mesh (Auto-Discovered)".to_string(),
                lat: fallback_lat,
                lon: fallback_lon,
                role: "🛰️ Federated Mesh Peer (Auto-Join)".to_string(),
            }
        });

    let (status, health_score, rtt_ms, last_seen_sec, eff_fail) = if is_local {
        ("ACTIVE / LOCAL".to_string(), 1, 1.0, 0, 0)
    } else {
        let st = online_state.as_deref().unwrap_or("UNKNOWN");
        let is_up = st == "ONLINE";
        let hs = if is_up { 1 } else { 0 };
        let status_str = if is_up {
            "ACTIVE / SYNCED".to_string()
        } else if st == "DOWN" {
            "HIBERNATING / DOWN".to_string()
        } else {
            "PROBING...".to_string()
        };
        let rtt = if is_up {
            (rtt_ewma * 10.0).round() / 10.0
        } else {
            0.0
        };
        let seen = last_ok_epoch.map(|ep| now_epoch_sec - ep).unwrap_or(-1);
        (status_str, hs, rtt, seen, fail_count)
    };

    let proto = if LEGACY_V1_PEERS.contains(&domain) { 1 } else { 2 };

    NodeGeoDetail {
        domain: domain.to_string(),
        node_name: meta.node_name,
        map_label: meta.map_label,
        location: meta.location,
        provider: meta.provider,
        lat: meta.lat,
        lon: meta.lon,
        role: meta.role,
        status,
        node_type: if is_local {
            "Local Node".to_string()
        } else {
            "Remote Peer (Tor v3)".to_string()
        },
        protocol_version: proto,
        auto_discovered,
        health_score,
        rtt_ms,
        last_seen_sec,
        fail_count: eff_fail,
    }
}

pub fn resolve_fast_lane_url(my_dom: &str, peer_onion: &str) -> Option<String> {
    if let Ok(raw_map) = std::env::var("FAST_LANE_PEERS_JSON") {
        let trimmed = raw_map.trim();
        if !trimmed.is_empty() {
            if let Ok(custom_map) = serde_json::from_str::<HashMap<String, String>>(trimmed) {
                if let Some(u) = custom_map.get(peer_onion) {
                    return Some(u.trim_end_matches('/').to_string());
                }
            }
        }
    }

    if (my_dom.starts_with("onion4zr3") || my_dom.starts_with("kn4u2xxl"))
        && COLOCATED_PVE_HS_PEERS.contains(&peer_onion)
    {
        return Some("http://127.0.0.1:8080".to_string());
    }
    if my_dom.starts_with("jz6urt6c") && peer_onion.starts_with("wfi3nwuz") {
        return Some("http://127.0.0.1:8082".to_string());
    }
    if my_dom.starts_with("wfi3nwuz") && peer_onion.starts_with("jz6urt6c") {
        return Some("http://127.0.0.1:8080".to_string());
    }
    if (my_dom.starts_with("ichzjrvw") || my_dom.starts_with("5s6w6556"))
        && (peer_onion.starts_with("ichzjrvw") || peer_onion.starts_with("5s6w6556"))
    {
        return Some("http://127.0.0.1:8080".to_string());
    }
    if (my_dom.starts_with("xzl3whmw")
        || my_dom.starts_with("o5yf3euk")
        || my_dom.starts_with("bk7iegv3"))
        && (peer_onion.starts_with("xzl3whmw")
            || peer_onion.starts_with("o5yf3euk")
            || peer_onion.starts_with("bk7iegv3"))
    {
        return Some("http://127.0.0.1:8080".to_string());
    }
    if my_dom.starts_with("e3a7jfpz") && peer_onion.starts_with("xememocn") {
        return Some("http://127.0.0.1:8082".to_string());
    }
    if my_dom.starts_with("xememocn") && peer_onion.starts_with("e3a7jfpz") {
        return Some("http://127.0.0.1:8080".to_string());
    }
    if my_dom.starts_with("onion4zr3") && peer_onion.starts_with("kn4u2xxl") {
        if let Ok(u) = std::env::var("SIBLING_NODE2_FAST_URL") {
            if !u.trim().is_empty() {
                return Some(u.trim().trim_end_matches('/').to_string());
            }
        }
    }
    if my_dom.starts_with("kn4u2xxl") && peer_onion.starts_with("onion4zr3") {
        if let Ok(u) = std::env::var("SIBLING_NODE1_FAST_URL") {
            if !u.trim().is_empty() {
                return Some(u.trim().trim_end_matches('/').to_string());
            }
        }
    }
    None
}
