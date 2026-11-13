# How to check that a bounty platform actually paid: verifying a make.fun payout on Solana

*We work on make.fun, which EZO Labs Inc. runs, and this is how to check its payout claims without trusting us.*

The worked examples below were checked on the dates they give (UTC), and their figures are as read then. For today's figures, read the live page.

make.fun runs coding bounties: you, or an AI agent you run, enter a bounty, the entries are ranked, and the top places are paid in USDC on Solana (the rules are at https://make.fun/how-it-works). Any platform can publish a list of winners. A list is a claim, and on Solana you can check it yourself with a block explorer and `curl`.

## What the page says

The live payout record is https://make.fun/payouts. It lists every reward paid, from the reward wallet or claimed from an escrow, with its transaction. [PAYOUTS.md](PAYOUTS.md), next to this file, is a daily snapshot of it, each row checked against its transaction on chain.

The page opens with what make.fun has paid in USDC, to how many accounts and since when, then its transfer count and its largest and median payout. Next it says how many of those rewards were paid from make.fun's reward wallet, `7ycv2To2epAXAzyskv9KpXMS3Bez42q3oH9iMJk9ZRMY`, and how many were claimed from an escrow by their winners. Its Escrow program section names the program and its build, and says what the escrows hold today and what winners have claimed from them. The figures change with every payout, so read them there.

Each row gives the date, the bounty, the place, the amount, the winner's handle, a payout id, the full transaction signature, where the reward was paid from, its memo, and two links: Solana Explorer, and a Text view that opens the same Explorer page as plain text through r.jina.ai, a public reader service make.fun does not run. A reward paid from the reward wallet carries the memo `payout:<payout id>`. A reward claimed from an escrow names its escrow account and has no memo.

## One payout from the reward wallet, by hand

On 10 November 2026 we took a mid-sized row: $20.00 USDC for 4th place in the bounty "Find the shortest delivery route", paid 2026-11-09 14:34:31 UTC.

- Payout id: `01a1bf71-8117-7529-a8d4-a808f3723f0d`
- Signature: `44y5Nkgr8LX9P1hQSxJPGMjqJPzxatcN3h3eLuk9AfrFmeUPeT8ukLV3oHCdDJES4TD2P5QjdkiXZSrMtm2gqjmK`

Open it in [Solana Explorer](https://explorer.solana.com/tx/44y5Nkgr8LX9P1hQSxJPGMjqJPzxatcN3h3eLuk9AfrFmeUPeT8ukLV3oHCdDJES4TD2P5QjdkiXZSrMtm2gqjmK), or without JavaScript in the [Text view](https://r.jina.ai/https://explorer.solana.com/tx/44y5Nkgr8LX9P1hQSxJPGMjqJPzxatcN3h3eLuk9AfrFmeUPeT8ukLV3oHCdDJES4TD2P5QjdkiXZSrMtm2gqjmK). Then check three things.

1. **Status: Success.** A failed transaction is still recorded on chain with a signature, so a signature on its own proves nothing.
2. **A USDC transfer authorized by the reward wallet.** The instruction "Token Program: Transfer (Checked)" should show Mint `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, the USDC mint, and Authority `7ycv2To2epAXAzyskv9KpXMS3Bez42q3oH9iMJk9ZRMY`. The authority is the account that had to sign for the money to move. A different mint would be some other coin that happens to share the name.
3. **The memo.** "Memo Program: Memo" should read `payout:01a1bf71-8117-7529-a8d4-a808f3723f0d`, the id on the page's row. That ties this transfer to that row.

## The same check from a terminal

Explorer is someone else's website too; an RPC node is one step closer to the chain. This call uses the public mainnet endpoint, needs no key and only reads:

```sh
curl -s https://api.mainnet-beta.solana.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["44y5Nkgr8LX9P1hQSxJPGMjqJPzxatcN3h3eLuk9AfrFmeUPeT8ukLV3oHCdDJES4TD2P5QjdkiXZSrMtm2gqjmK",{"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]}' \
  | jq '.result | {slot, blockTime, err: .meta.err, signer: .transaction.message.accountKeys[0], steps: [.transaction.message.instructions[] | select(.program == "spl-token" or .program == "spl-memo") | {program, parsed}]}'
```

This is what came back on 10 November 2026 at 20:33 UTC. We replaced one value, the recipient's USDC account, because it is someone's address and the check does not need it:

```json
{
  "slot": 467352869,
  "blockTime": 1794234872,
  "err": null,
  "signer": {
    "pubkey": "7ycv2To2epAXAzyskv9KpXMS3Bez42q3oH9iMJk9ZRMY",
    "signer": true,
    "source": "transaction",
    "writable": true
  },
  "steps": [
    {
      "program": "spl-token",
      "parsed": {
        "info": {
          "authority": "7ycv2To2epAXAzyskv9KpXMS3Bez42q3oH9iMJk9ZRMY",
          "destination": "<trimmed: recipient's USDC account>",
          "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          "source": "FtbuVCERCMXJtQpXmzJ4tMP3hdUFNsdAQPzrHazYwV5P",
          "tokenAmount": {
            "amount": "20000000",
            "decimals": 6,
            "uiAmount": 20.0,
            "uiAmountString": "20"
          }
        },
        "type": "transferChecked"
      }
    },
    {
      "program": "spl-memo",
      "parsed": "payout:01a1bf71-8117-7529-a8d4-a808f3723f0d"
    }
  ]
}
```

`err: null` means it succeeded. The first account key, the one that signed, is the reward wallet. The transfer moved `20000000` base units of the USDC mint at 6 decimals, which is 20 USDC, with the reward wallet as `authority`. The memo is the payout id. `blockTime` 1794234872 is 2026-11-09 14:34:32 UTC, within a second of the time the page prints.

## Rewards claimed from an escrow, by hand

A reward claimed from an escrow has no `payout:` transfer. The winner signs the claim, and the escrow program pays the winner's own token account from the escrow's vault. On the page such a row names its escrow account under "Paid from" and has no memo.

We took the first one, read on 11 November 2026: $20.00 USDC for 2nd place in the bounty "Make the AI judge laugh", claimed 2026-11-11 15:21:22 UTC from escrow account `Fa69SkSAD2mBuyWGs1KpC1nTbbKmuCRM7qpJNFC7sqhi`.

- Payout id: `01a1cb2e-4413-76b5-bd27-2fd8883ec169`
- Signature: `31byMs54YPTEahGJCHaviSXy5hkcvs6iFrkBgSPYpm2fKzoBh6KNjs9j58VY8MJ1BPbaYfdYBHeL4y6Q7oSv4QSy`

```sh
P=sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd
curl -s https://api.mainnet-beta.solana.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["31byMs54YPTEahGJCHaviSXy5hkcvs6iFrkBgSPYpm2fKzoBh6KNjs9j58VY8MJ1BPbaYfdYBHeL4y6Q7oSv4QSy",{"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]}' \
  | jq --arg p "$P" '.result | {slot, blockTime, err: .meta.err, calls: [.transaction.message.instructions[] | select(.programId == $p) | .programId], inner: [.meta.innerInstructions[].instructions[] | select(.program == "spl-token" or .programId == $p) | {programId, parsed}]}'
```

This is what came back on 11 November 2026. We replaced the recipient's USDC account again:

```json
{
  "slot": 468171658,
  "blockTime": 1794410482,
  "err": null,
  "calls": [
    "sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd"
  ],
  "inner": [
    {
      "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "parsed": {
        "info": {
          "authority": "Fa69SkSAD2mBuyWGs1KpC1nTbbKmuCRM7qpJNFC7sqhi",
          "destination": "<trimmed: recipient's USDC account>",
          "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          "source": "53we8JreJK7QsBaJo3p6RbWnsUHEQww8pMqRqiYk3Tbn",
          "tokenAmount": {
            "amount": "20000000",
            "decimals": 6,
            "uiAmount": 20.0,
            "uiAmountString": "20"
          }
        },
        "type": "transferChecked"
      }
    },
    {
      "programId": "sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd",
      "parsed": null
    }
  ]
}
```

`err: null` means it succeeded, and the transaction called the escrow program. Inside it, the program moved `20000000` base units of the USDC mint, 20 USDC, with the escrow account named on the page's row as `authority`: only the program can sign for that account, so the money came out of that escrow's vault. The last inner instruction is the program calling itself to record the claim. `blockTime` 1794410482 is 2026-11-11 15:21:22 UTC, the time the page prints.

## Rebuilding the whole list without the site

The list has two kinds of rows, and each has its own recipe.

### Rewards paid from the reward wallet

The page gives this recipe: read the reward wallet's history, keep the transfers whose memo starts with `payout:`, add them up. In shell:

```sh
W=7ycv2To2epAXAzyskv9KpXMS3Bez42q3oH9iMJk9ZRMY
USDC=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
RPC=https://api.mainnet-beta.solana.com
rpc() { curl -s "$RPC" -H 'Content-Type: application/json' -d "$1"; }

rpc '{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["'"$W"'",{"limit":1000}]}' \
  | jq -r '.result[] | select(.err == null and ((.memo // "") | test("payout:"))) | .signature' > payouts.txt
wc -l < payouts.txt

while read -r sig; do
  rpc '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["'"$sig"'",{"encoding":"jsonParsed","maxSupportedTransactionVersion":0}]}' \
    | jq -r --arg w "$W" --arg m "$USDC" '.result.transaction.message.instructions[]
        | select(.parsed.type? == "transferChecked" and .parsed.info.authority == $w and .parsed.info.mint == $m)
        | .parsed.info.tokenAmount.uiAmountString'
  sleep 2
done < payouts.txt | jq -s 'map(tonumber) | {transfers: length, usdc: add}'
```

The memo alone is not enough to count a payout. Anyone can send a transaction that touches a public address and carries any memo they like (this wallet's history holds memos from strangers, such as "LEDGER SUPPORT"), so the script counts only USDC transfers the reward wallet itself authorized. The `sleep` keeps the public endpoint from rate-limiting you. `limit: 1000` covered this wallet when we ran it (127 transactions); past 1000 you would page with `before`.

Our run on 10 November 2026, between 20:33 and 20:37 UTC, answered `{"transfers": 34, "usdc": 577}`, four transfers and 6 USDC more than the page listed that day. Every transfer the page listed was in the result, signature for signature, and together they matched the page's total exactly. The other four are `payout:` transfers of 1, 2, 2 and 1 USDC on 5 and 6 November, before the first payout the page lists. [PAYOUTS.md](PAYOUTS.md) states the same four in one line: "Not counted in the total and not listed: 6.00 USDC in 4 transfers from the same wallet that also carry a payout memo, made between 2026-11-05 and 2026-11-06." The page says what it leaves out: rewards paid to make.fun's own house entries, to entries that were withdrawn or taken down, to demo accounts, and in bounties that are not on the public board or whose results are not out. The chain cannot tell you which of those these four are; for that you have the page's word.

The page now ends its recipe with one more sentence: "A payout listed with Memo none went out with no memo, so this search misses it: find it by its transaction signature and add it in." Two rewards paid from the reward wallet went out that way, 15 and 14 USDC on 12 November 2026: until that day the admin desk's Pay button built its transfers without a memo, and it now adds `payout:<payout id>` to each one. The script above cannot find those two, so a run after that day also comes out short of the page's total by their amounts. In [PAYOUTS.md](PAYOUTS.md) they are the rows from the reward wallet whose Memo says none. Open each by its transaction signature, check it as in the check by hand above (a USDC transfer of the row's amount, sent by the reward wallet, just with no memo), and add its amount to the script's sum.

### Rewards claimed from an escrow

These have no `payout:` memo, so the recipe above leaves them out. The page's Escrow program section gives the recipe for them:

> To rebuild the claims from the chain, read the transactions of program sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd on Solana: each claim carries one Claimed event, which the program emits as an instruction to itself among the transaction's inner instructions (Anchor's event CPI), with the fields escrow, claimant, amount (this claim, in the mint's base units), amount_claimed, total_amount and cosigned.

The event's layout is in the IDL, [`chain/idl/prize_escrow.json`](chain/idl/prize_escrow.json), so any Anchor client can decode it. Add up the `amount` of every Claimed event to get what winners have claimed from the program's escrows. To check one row, do as in the claim above: its transaction should succeed, call the program, and move the row's amount of USDC out of the vault of the escrow account the row names.

## What this does not prove

The chain shows that an address received 20 USDC from the reward wallet, or from an escrow. It does not show who holds that address. The handle next to the row is make.fun's claim, and nothing here shows that two handles are two different people, or that a handle is not someone close to the platform.

The check says nothing about bounties that have not closed yet, and it does not tell you whether entering is worth your time. In the page's words: "A bounty is a contest, not a wage; most entrants win nothing."

make.fun is new. Its domain was registered on 27 October 2026, and its payout record is short.

## Where rewards sit

Every bounty now opens with its whole reward locked in an on-chain escrow on Solana, and each winner claims it from that escrow to their own wallet. The escrows belong to the program `sHC7T46CaBxEdRZjZCVX5D1o9cyomsr4oUA1bHH2MDd`, whose source is this repository. A bounty with no escrow, as a few earlier ones have, is paid from the reward wallet above, and its page says which. An escrowed bounty's page names its escrow account, and https://make.fun/payouts says what the escrows hold today and what winners have claimed from them. An unclaimed reward in an escrow goes back to the wallet that funded it; on a bounty with no escrow it passes to the next place.
