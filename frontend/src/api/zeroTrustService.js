/**
 * Zero Trust API Service
 * Handles all Zero Trust pipeline API calls
 */

import api from './apiConfig';

export const zeroTrustService = {
  /**
   * Health check
   */
  healthCheck: async () => {
    try {
      const response = await api.get('/health');
      return response.data;
    } catch (error) {
      console.error('Health check failed:', error);
      throw error;
    }
  },

  /**
   * Verify source integrity
   */
  verifySourceIntegrity: async (data) => {
    try {
      const response = await api.post('/api/zero-trust/source/verify', data);
      return response.data;
    } catch (error) {
      console.error('Source integrity verification failed:', error);
      throw error;
    }
  },

  /**
   * Check dependencies
   */
  checkDependencies: async (manifest) => {
    try {
      const response = await api.post('/api/zero-trust/deps/check', { manifest });
      return response.data;
    } catch (error) {
      console.error('Dependency check failed:', error);
      throw error;
    }
  },

  /**
   * Record to blockchain ledger
   */
  recordToBlockchain: async (data) => {
    try {
      const response = await api.post('/api/zero-trust/ledger/record', data);
      return response.data;
    } catch (error) {
      console.error('Blockchain recording failed:', error);
      throw error;
    }
  },

  /**
   * Verify artifact
   */
  verifyArtifact: async (data) => {
    try {
      const response = await api.post('/api/zero-trust/artifact/verify', data);
      return response.data;
    } catch (error) {
      console.error('Artifact verification failed:', error);
      throw error;
    }
  },

  /**
   * Get security data
   */
  getSecurityScenarios: async () => {
    try {
      const response = await api.get('/api/data/real_world_security_scenarios');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch security scenarios:', error);
      throw error;
    }
  },

  /**
   * Get blockchain architecture data
   */
  getBlockchainArchitecture: async () => {
    try {
      const response = await api.get('/api/data/blockchain_trust_architecture');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch blockchain architecture:', error);
      throw error;
    }
  },
};

export default zeroTrustService;
