//! Gmail IMAP extensions (`X-GM-EXT-1`).
//!
//! See <https://developers.google.com/gmail/imap/imap-extensions>.
//!
//! Only `X-GM-MSGID` is supported for now.

use imap_types::fetch::MessageDataItem;
use nom::{bytes::streaming::tag_no_case, combinator::map, sequence::preceded};

use crate::{core::number64, decode::IMAPResult};

/// ```abnf
/// msg-att-x-gm-msgid = "X-GM-MSGID" SP number64
/// ```
pub(crate) fn x_gm_msgid(input: &[u8]) -> IMAPResult<&[u8], MessageDataItem> {
    map(
        preceded(tag_no_case(b"X-GM-MSGID "), number64),
        MessageDataItem::XGmMsgId,
    )(input)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use imap_types::{
        command::{Command, CommandBody},
        core::Vec1,
        fetch::{MacroOrMessageDataItemNames, MessageDataItem, MessageDataItemName},
        response::{Data, Response},
    };

    use crate::testing::{kat_inverse_command, kat_inverse_response, known_answer_test_encode};

    #[test]
    fn test_encode_x_gm_msgid() {
        known_answer_test_encode((MessageDataItemName::XGmMsgId, b"X-GM-MSGID"));
        known_answer_test_encode((
            MessageDataItem::XGmMsgId(1278455344230334865),
            b"X-GM-MSGID 1278455344230334865",
        ));
    }

    #[test]
    fn test_kat_inverse_command_fetch_x_gm_msgid() {
        kat_inverse_command(&[(
            b"A UID FETCH 1 (UID X-GM-MSGID)\r\n".as_ref(),
            b"".as_ref(),
            Command::new(
                "A",
                CommandBody::fetch(
                    "1",
                    MacroOrMessageDataItemNames::MessageDataItemNames(vec![
                        MessageDataItemName::Uid,
                        MessageDataItemName::XGmMsgId,
                    ]),
                    true,
                )
                .unwrap(),
            )
            .unwrap(),
        )]);
    }

    #[test]
    fn test_kat_inverse_response_fetch_x_gm_msgid() {
        kat_inverse_response(&[
            (
                b"* 1 FETCH (X-GM-MSGID 1278455344230334865 UID 7)\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::Fetch {
                    seq: NonZeroU32::new(1).unwrap(),
                    items: Vec1::try_from(vec![
                        MessageDataItem::XGmMsgId(1278455344230334865),
                        MessageDataItem::Uid(NonZeroU32::new(7).unwrap()),
                    ])
                    .unwrap(),
                }),
            ),
            (
                b"* 2 FETCH (UID 8 X-GM-MSGID 18446744073709551615)\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::Fetch {
                    seq: NonZeroU32::new(2).unwrap(),
                    items: Vec1::try_from(vec![
                        MessageDataItem::Uid(NonZeroU32::new(8).unwrap()),
                        MessageDataItem::XGmMsgId(u64::MAX),
                    ])
                    .unwrap(),
                }),
            ),
        ]);
    }

    #[test]
    fn test_x_gm_msgid_out_of_range_is_rejected() {
        use crate::{ResponseCodec, decode::Decoder};

        assert!(
            ResponseCodec::default()
                .decode(b"* 1 FETCH (X-GM-MSGID 18446744073709551616)\r\n")
                .is_err()
        );
    }
}
