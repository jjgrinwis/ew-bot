/*
(c) Copyright 2024 Akamai Technologies, Inc. Licensed under Apache 2 license.

Version: 0.0.14
Purpose: if the defined bidblocks is exactly the same as AF_FIREWALL bid rules, generate a response.
This version there should be an exact match but feel free to modify the check
*/

// the exact list of BIDS you want to block on.
const staticRuleIds: string = "3904000:3904003:3904006:3904042";

// the http response when there is a BID match
const bidMatchResponse = {
  status: 403,
  headers: { "Content-Type": "application/json;charset=utf-8" },
  body: JSON.stringify({ error: staticRuleIds }),
  statusText: "Denied Response",
};

// unpack our response so it can be feed into responseWith
const { status, headers, body, statusText } = bidMatchResponse;

/**
 * Check if all elements in array1 exists in array2.
 * @param array1 A list with all the individual firewall rule ids.
 * @param array2 A list you want to compare array1 against.
 * @returns true if all elements in array1 exists in array2
 */
const isSubset = (array1: string[], array2: string[]) =>
  array1.every((element) => array2.includes(element));

/**
 * Check if both arrays are exactly the same
 * @param array1 A list with all the individual firewall rule ids.
 * @param array2 A list with the individual firewall rule ids you want to compare array1 against.
 * @returns true if array1 and array2 are exactly the same
 */
const isEqual = (array1: string[], array2: string[]) =>
  JSON.stringify(array1) === JSON.stringify(array2);

/**
 * Creates a sorted list of Browser Impersonator Detection (BID) rules starting with '3904'.
 * It expect a list of firewall rules like from a string of firewall rules like 3904000:3904003:3904006:3904042:BOT-BROWSER-IMPERSONATOR
 * @param bids A string containing Akamai triggered firewall rules, separated by a colon (':').
 * @returns An array of only the BID rules, starting with '3904', sorted alphabetically.
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
  const detectedRuleIds: string = request.getVariable("PMUSER_FW_RULES");

  /* 
  Only take action if the FW_RULES is set. 
  This should be done in delivery config not to waste time and EW calls.
  */
  if (detectedRuleIds !== null && detectedRuleIds.length > 0) {
    // this version detected and pre-defined list should be exactly the same
    if (isEqual(createBidList(detectedRuleIds), createBidList(staticRuleIds))) {
      request.respondWith(status, headers, body, statusText);
    }
  }
}
