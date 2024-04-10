const bidBlock: string = "3904000:3904003:3904006:3904042";

/**
 * Creates a sorted list of Browser Impersonator Detection (BID) rules starting with '3904' from a string of firewall rules.
 * @param bids A string containing firwallrules separated by colon (':').
 * @returns An array of only the bid rules, starting with '3904', sorted alphabetically.
 */
const createBidList = (bids: string) => {
  // our regex just to only get the BID rules which start with 3904
  const regexPattern: RegExp = /^3904/;

  const ruleIdsList: string[] = bids.split(":");

  return ruleIdsList.filter((item) => regexPattern.test(item)).sort();
};

/**
 * Checks if two string arrays are equal.
 * @param a The first string array.
 * @param b The second string array.
 * @returns True if the arrays are equal, false otherwise.
 */
const equalsCheck = (a: string[], b: string[]) => {
  return JSON.stringify(a) === JSON.stringify(b);
};

const ruleIds = "3904000:3904003:3904006:3904042";

if (ruleIds !== undefined) {
  if (equalsCheck(createBidList(ruleIds), createBidList(bidBlock))) {
    console.log("true");
  } else {
    console.log("false");
  }
}
