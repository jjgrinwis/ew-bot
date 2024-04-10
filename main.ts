/*
(c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.

Version: 0.0.6
Purpose: if the defined bidblocks is exactly the same as AF_FIREWALL bid rules, generate a response.
This version there should be an exact match but feel free to modify the check
*/

// the exact list of BIDS you want to block on.
const bidBlock: string = "3904000:3904003:3904006:3904042";

/**
 * Creates a sorted list of Browser Impersonator Detection (BID) rules starting with '3904' from a string of firewall rules.
 * @param bids A string containing firewall rules, separated by a colon (':').
 * @returns An array of only the bid rules, starting with '3904', sorted alphabetically.
 */
const createBidList = (bids: string) => {
  // our regex just to only get the BID rules which start with 3904
  const regexPattern: RegExp = /^3904/;
  const ruleIdsList: string[] = bids.split(":");

  return ruleIdsList.filter((item) => regexPattern.test(item)).sort();
};

export async function onClientRequest(request: EW.IngressOriginRequest) {
  /*
    We're forwarding internal AK_FIREWALL rules via PMUSER var.
    BID rules for example look like this: 3904000:3904003:3904006:3904042:BOT-BROWSER-IMPERSONATOR
    https://techdocs.akamai.com/app-api-protector/docs/bot-detn-methods-rule-ids#browser-impersonator-detection
*/

  // PMUSER_FW_RULES should be filled with AK_FIREWALL var in delivery configuration
  const ruleIds: string = request.getVariable("PMUSER_FW_RULES");

  /* 
  Only take action if the FW_RULES is set. 
  This should be done in delivery config not to waste time and EW calls.
  */
  if (ruleIds !== undefined) {
    if (
      createBidList(ruleIds).toString() === createBidList(bidBlock).toString()
    ) {
      request.setHeader("x-ew-bid-hit", "true");
      request.respondWith(
        403,
        { "Content-Type": ["application/json;charset=utf-8"] },
        JSON.stringify({ error: bidBlock }),
        "Denied Response"
      );
    } else {
      request.setHeader("x-ew-bidblock-hit", "false");
    }
  }
}
