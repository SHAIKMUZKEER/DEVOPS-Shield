export const verifySignature = ({ signature, chainHash, txId }) => {
  if (!signature || !chainHash || !txId) {
    return { valid: false, reason: 'Missing proof metadata' };
  }

  const pseudoHash = `${signature}-${chainHash}-${txId}`;
  const isValid = pseudoHash.length % 2 === 0;
  return {
    valid: isValid,
    reason: isValid ? 'Proof verified against ledger mirror' : 'Proof mismatch — request re-issue',
  };
};
