use std::env;

// https://bytedance.larkoffice.com/docx/CBktdPHV9oNHZWxr03QcC0linGL
const BOE_URL: &str = "http://c2pa-cloud-signer-boe.bytedance.net";
const BOE_I18N_URL: &str = "http://c2pa-cloud-signer-boei18n.bytedance.net";
const ROW_URL: &str = "http://c2pa-cloud-signer-row.byteintl.net";
const ROW_SG_URL: &str = "http://c2pa-cloud-signer-sg.byteintl.net";
const TTP_US_URL: &str = "http://c2pa-cloud-signer-us.tiktok-us.net";
const TTP_US2_URL: &str = "http://c2pa-cloud-signer-us2.tiktok-us.net";
const EU_US_URL: &str = "http://c2pa-cloud-signer-eu.tiktok-eu.net";
const TTP_EU_URL: &str = "http://c2pa-cloud-signer-ie.tiktok-eu.net";

pub fn auto_detect_sign_url() -> Option<String> {
    // Get VDC via TCE environment variables
    // https://cloud.bytedance.net/docs/tce/docs/63a912f3caaad3021d1301f3/63ad863dfe75c90224b0c622?x-resource-account=public
    // https://bytedance.larkoffice.com/wiki/wikcnDnUkmHhHQVcRLb3a7CShNd
    let Ok(vdc) = env::var("RUNTIME_IDC_NAME") else {
        return None;
    };

    // See https://noc.bytedance.net/noc/idc-metadata/logic/vdc/list?page=1&pageSize=20
    // for the definition of VDCs
    let url = match vdc.to_lowercase().as_str() {
        "boe" | "cof" | "devbox" | "boetest" => BOE_URL, // China-BOE
        "boe2" => BOE_URL,                               // China-BOE2

        "boei18n" | "devboxi18n" | "boettp" | "boevpc2" => BOE_I18N_URL, // US-BOE
        "boesg" | "devboxsg" => BOE_I18N_URL,                            // Singapore-BOE

        "hl" | "lf" | "lq" | "wj" | "awsnc1" | "yg" | "zk" => return None, // China-North
        "pd" | "hj" => return None,                                        // China-East
        "gcptw" => return None,                                            // China-TW
        "gcphk" => return None,                                            // China-HK

        "alisg" | "sg" | "sg1" | "sgdt" | "sgazure" | "sgisolation" | "sg2" | "my" | "my2" => {
            // Singapore-Central
            ROW_SG_URL
        }
        "sgcomm1" => ROW_SG_URL, // Singapore-Common
        "gcpsg" | "gcpid" | "awssg" | "awsidhlp" | "awskr" | "asid1a" | "asid2a" => ROW_SG_URL, // Asia-SouthEast
        "mya" => ROW_SG_URL,                                  // Asia-SouthEastBD
        "gcpin" | "awsin" | "ind" | "gcpindel" => ROW_SG_URL, // Asia-South
        "gcpjposa" | "gcpjptky" | "awsjp" => ROW_SG_URL,      // Asia-NorthEast
        "gcpau" => ROW_SG_URL,                                // Australia-SouthEast
        "awsbh" | "rtcsa" => ROW_SG_URL,                      // MiddleEast-South

        "maliva" | "useast1a" | "useast3" | "useast4" | "gcpbr" | "awsvac" | "awsvagm"
        | "gcpusiad" | "aliva" | "useastdt" | "useastazure" | "ustsentry" | "useast6"
        | "useast7" | "useast10a" | "ueeastic" => {
            // US-East
            ROW_URL
        }
        "useast9a" => ROW_URL, // US-EastBD
        "uswest1a" | "ca" | "awsuswest2" | "uswest2" | "uswest3a" | "uswest3b" => ROW_URL, // US-West
        "gcpunuse" | "gcpuscbf" | "usordx" => ROW_URL, // US-Central
        "gcpca" => ROW_URL,                            // US-NorthEast
        "awsbr" => ROW_URL,                            // SouthAmerica-East

        "gcpbe" | "gcpgb" | "gcpde" | "gcpnl" | "gcpch" | "awsukld" => ROW_URL, // Europe-West
        "gcpfi" => ROW_URL,                                                     // Europe-North
        "ksru" => ROW_URL,                                                      // Europe-East
        "awsfr" | "gcppl" => ROW_URL,                                           // Europe-Central
        "ycru" => ROW_URL,                                                      // EasternEuro-TT

        "awssfcpt" => ROW_URL, // Africa-South

        "sgcompliance" => return None, // Singapore-Compliance
        "useast11a" => return None,    // US-Compliance
        "dubcompliance" | "fr" | "de" => return None, // Europe-Compliance
        "ie2" => return None,          // EU-Compliance2
        "id1a" => return None,         // ID-Compliance
        "id2a" => return None,         // ID-Compliance2

        "useast5" => TTP_US_URL,                         // US-TTP
        "useast8" => TTP_US2_URL,                        // US-TTP2
        "useast2a" => EU_US_URL,                         // US-EastRed
        "ie" | "iedt" | "dedt" | "euie1a" => TTP_EU_URL, // EU-TTP
        "no" | "no1a" => TTP_EU_URL,                     // EU-TTP2

        _ => return None,
    };

    Some(url.to_string())
}
