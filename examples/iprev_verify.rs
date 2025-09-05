    use std::{
        net::IpAddr,
        str::FromStr,
        sync::Arc,
    };

    use mail_auth::{IprevOutput, MessageAuthenticator, Parameters,IprevResult};
    #[tokio::main]
    async fn main() {
        check_iprev_direct().await;
        check_iprev_full().await;
    }
    async fn check_iprev_direct() {
        let resolver = MessageAuthenticator::new_cloudflare().unwrap();
        let arc = Arc::new(vec!["one.one.one.one.".to_string()]);
        let params = Parameters::new(IpAddr::from_str("1.1.1.1").unwrap());
        assert_eq!(
            resolver
                .verify_iprev("one.one.one.one.".to_string(), params)
                .await,
            IprevOutput {
                ptr: Some(arc),
                result: crate::IprevResult::Pass
            }
        );
    }
    async fn check_iprev_full() {
        let resolver = MessageAuthenticator::new_cloudflare().unwrap();
        let arc = Arc::new(vec!["ec2-54-215-62-21.us-west-1.compute.amazonaws.com.".to_string()]);
        let params = Parameters::new(IpAddr::from_str("54.215.62.21").unwrap());
        assert_eq!(
            resolver
                .verify_iprev("ec2-54-215-62-21.us-west-1.compute.amazonaws.com.".to_string(), params)
                .await,
            IprevOutput {
                ptr: Some(arc),
                result: crate::IprevResult::Pass
            }
        );
    }
