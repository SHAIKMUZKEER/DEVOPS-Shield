"""
Dependency Sentinel
Namespace locking and supply chain security for preventing dependency confusion attacks
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import json
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger

logger = get_logger(__name__)

class NamespaceLock:
    """Manages namespace locking for package security"""

    def __init__(self):
        self.locked_namespaces = self._load_locked_namespaces()
        self.allowed_packages = self._load_allowed_packages()
        self.blocked_patterns = self._load_blocked_patterns()

    def _load_locked_namespaces(self) -> Dict[str, Dict[str, Any]]:
        """Load namespace locking rules"""
        # Default locked namespaces based on common attacks
        return {
            'pytorch': {
                'description': 'PyTorch ecosystem protection',
                'patterns': [r'^pytorch-', r'^torch-'],
                'official_owners': ['pytorch', 'facebookresearch'],
                'risk_level': 'critical'
            },
            'apple': {
                'description': 'Apple ecosystem protection',
                'patterns': [r'^apple-', r'^ios-', r'^macos-'],
                'official_owners': ['apple', 'apple-opensource'],
                'risk_level': 'critical'
            },
            'tensorflow': {
                'description': 'TensorFlow ecosystem protection',
                'patterns': [r'^tensorflow-', r'^tf-'],
                'official_owners': ['tensorflow', 'google'],
                'risk_level': 'critical'
            },
            'microsoft': {
                'description': 'Microsoft ecosystem protection',
                'patterns': [r'^microsoft-', r'^azure-', r'^dotnet-'],
                'official_owners': ['microsoft', 'azure-sdk'],
                'risk_level': 'high'
            },
            'aws': {
                'description': 'AWS ecosystem protection',
                'patterns': [r'^aws-', r'^boto3-', r'^botocore-'],
                'official_owners': ['aws', 'boto'],
                'risk_level': 'high'
            },
            'google': {
                'description': 'Google ecosystem protection',
                'patterns': [r'^google-', r'^gcp-', r'^firebase-'],
                'official_owners': ['google', 'googleapis', 'google-cloud'],
                'risk_level': 'high'
            }
        }

    def _load_allowed_packages(self) -> Set[str]:
        """Load explicitly allowed packages"""
        return {
            'requests', 'numpy', 'pandas', 'flask', 'django', 'fastapi',
            'scikit-learn', 'matplotlib', 'pytest', 'black', 'isort',
            'click', 'rich', 'tqdm', 'python-dotenv', 'uvicorn'
        }

    def _load_blocked_patterns(self) -> List[str]:
        """Load blocked package name patterns"""
        return [
            r'^.*-internal$',
            r'^.*-private$',
            r'^.*-corp$',
            r'^.*-company$',
            r'^.*-enterprise$',
            r'^test-.*-package$',
            r'^.*-staging$',
            r'^.*-dev$',
            r'^.*-alpha$',
            r'^.*-beta$'
        ]

    def check_namespace_lock(self, package_name: str, version: str = None) -> Dict[str, Any]:
        """
        Check if package violates namespace locking rules

        Args:
            package_name: Name of the package
            version: Version of the package

        Returns:
            Check result with violation details
        """
        violations = []
        risk_score = 0.0

        # Check against locked namespaces
        for namespace, rules in self.locked_namespaces.items():
            for pattern in rules['patterns']:
                if re.match(pattern, package_name, re.IGNORECASE):
                    violations.append({
                        'type': 'namespace_lock_violation',
                        'namespace': namespace,
                        'description': rules['description'],
                        'risk_level': rules['risk_level'],
                        'pattern': pattern,
                        'package': package_name
                    })
                    risk_score += 0.8 if rules['risk_level'] == 'critical' else 0.6
                    break

        # Check against blocked patterns
        for pattern in self.blocked_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                violations.append({
                    'type': 'blocked_pattern',
                    'pattern': pattern,
                    'package': package_name,
                    'risk_level': 'high'
                })
                risk_score += 0.5

        # Check for suspicious naming patterns
        suspicious_indicators = self._check_suspicious_naming(package_name)
        if suspicious_indicators:
            for indicator in suspicious_indicators:
                violations.append({
                    'type': 'suspicious_naming',
                    'indicator': indicator,
                    'package': package_name,
                    'risk_level': 'medium'
                })
                risk_score += 0.3

        return {
            'package': package_name,
            'version': version,
            'violations': violations,
            'risk_score': min(risk_score, 1.0),
            'approved': len(violations) == 0,
            'violation_count': len(violations)
        }

    def _check_suspicious_naming(self, package_name: str) -> List[str]:
        """Check for suspicious package naming patterns"""
        indicators = []

        # Check for typosquatting attempts
        common_packages = ['requests', 'numpy', 'pandas', 'flask', 'django', 'fastapi']
        for common in common_packages:
            if self._is_typosquatting(package_name, common):
                indicators.append(f'potential_typosquatting_of_{common}')

        # Check for high entropy names (random-looking)
        if self._has_high_entropy(package_name):
            indicators.append('high_entropy_name')

        # Check for excessive hyphens or underscores
        separator_count = package_name.count('-') + package_name.count('_')
        if separator_count > 3:
            indicators.append('excessive_separators')

        # Check for numbers in suspicious positions
        if re.search(r'\d{4,}', package_name):  # 4+ consecutive digits
            indicators.append('suspicious_number_sequence')

        return indicators

    def _is_typosquatting(self, name1: str, name2: str) -> bool:
        """Check if name1 is a typosquatting attempt of name2"""
        if name1 == name2 or len(name1) != len(name2):
            return False

        # Simple edit distance check
        differences = sum(c1 != c2 for c1, c2 in zip(name1, name2))
        return differences <= 2  # Allow up to 2 character differences

    def _has_high_entropy(self, name: str) -> bool:
        """Check if package name has high entropy (random-looking)"""
        if len(name) < 10:
            return False

        # Calculate character frequency entropy
        from collections import Counter
        char_counts = Counter(name.lower())
        total_chars = len(name)

        entropy = 0
        for count in char_counts.values():
            p = count / total_chars
            entropy -= p * (p ** 0.5)  # Simplified entropy calculation

        return entropy > 2.5  # Threshold for high entropy

class SupplyChainAnalyzer:
    """Analyzes supply chain security risks"""

    def __init__(self):
        self.vulnerable_packages = self._load_vulnerability_database()
        self.malicious_packages = self._load_malicious_packages()

    def _load_vulnerability_database(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load known vulnerable package versions"""
        return {
            'requests': [
                {'version': '2.0.0', 'cve': 'CVE-2023-1234', 'severity': 'high'},
                {'version': '2.1.0', 'cve': 'CVE-2023-5678', 'severity': 'critical'}
            ],
            'urllib3': [
                {'version': '1.25.0', 'cve': 'CVE-2023-9012', 'severity': 'medium'}
            ],
            'cryptography': [
                {'version': '1.0.0', 'cve': 'CVE-2023-3456', 'severity': 'high'}
            ]
        }

    def _load_malicious_packages(self) -> Set[str]:
        """Load known malicious packages"""
        return {
            'fake-requests',
            'malicious-numpy',
            'trojan-pandas',
            'evil-flask'
        }

    def analyze_dependencies(self, dependencies: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze dependencies for supply chain risks

        Args:
            dependencies: Dict of package_name -> version

        Returns:
            Analysis results
        """
        risks = []
        total_risk_score = 0.0

        for package_name, version in dependencies.items():
            package_risks = []

            # Check for known malicious packages
            if package_name in self.malicious_packages:
                package_risks.append({
                    'type': 'known_malicious',
                    'severity': 'critical',
                    'description': f'Package {package_name} is known to be malicious'
                })
                total_risk_score += 1.0

            # Check for vulnerable versions
            if package_name in self.vulnerable_packages:
                for vuln in self.vulnerable_packages[package_name]:
                    if version == vuln['version']:
                        package_risks.append({
                            'type': 'known_vulnerability',
                            'severity': vuln['severity'],
                            'cve': vuln['cve'],
                            'description': f'Version {version} has known vulnerability {vuln["cve"]}'
                        })
                        severity_score = {'low': 0.2, 'medium': 0.5, 'high': 0.7, 'critical': 1.0}
                        total_risk_score += severity_score.get(vuln['severity'], 0.5)

            # Check for dependency confusion potential
            confusion_risk = self._check_dependency_confusion(package_name, version)
            if confusion_risk:
                package_risks.append(confusion_risk)
                total_risk_score += 0.6

            if package_risks:
                risks.append({
                    'package': package_name,
                    'version': version,
                    'risks': package_risks
                })

        return {
            'dependencies_analyzed': len(dependencies),
            'risky_dependencies': len(risks),
            'total_risk_score': min(total_risk_score, 1.0),
            'risks': risks,
            'approved': total_risk_score < 0.5  # Allow if risk is below 50%
        }

    def _check_dependency_confusion(self, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Check for dependency confusion vulnerabilities"""
        # Check for packages that might be confused with internal packages
        internal_indicators = ['internal', 'private', 'corp', 'company']

        for indicator in internal_indicators:
            if indicator in package_name.lower():
                return {
                    'type': 'dependency_confusion_risk',
                    'severity': 'high',
                    'description': f'Package name contains internal indicator "{indicator}" - potential dependency confusion'
                }

        # Check for packages with suspicious version patterns
        if re.match(r'^\d+\.\d+\.\d+-internal$', version):
            return {
                'type': 'suspicious_version',
                'severity': 'medium',
                'description': f'Version {version} follows internal versioning pattern'
            }

        return None

class DependencySentinel:
    """Main dependency security sentinel"""

    def __init__(self):
        self.namespace_lock = NamespaceLock()
        self.supply_chain_analyzer = SupplyChainAnalyzer()

    def check_dependencies(self, manifest: Dict[str, str]) -> Dict[str, Any]:
        """
        Comprehensive dependency security check

        Args:
            manifest: Dict of package_name -> version

        Returns:
            Security check results
        """
        logger.info(f"Dependency Sentinel checking {len(manifest)} packages")

        blocked_packages = []
        reasons = []
        total_risk_score = 0.0

        # Check each dependency
        for package_name, version in manifest.items():
            # Namespace locking check
            lock_result = self.namespace_lock.check_namespace_lock(package_name, version)
            if not lock_result['approved']:
                blocked_packages.append(package_name)
                for violation in lock_result['violations']:
                    reasons.append(f"Namespace lock violation: {violation['description']} ({package_name})")
                total_risk_score += lock_result['risk_score']

        # Supply chain analysis
        supply_chain_result = self.supply_chain_analyzer.analyze_dependencies(manifest)
        if not supply_chain_result['approved']:
            for risk in supply_chain_result['risks']:
                for package_risk in risk['risks']:
                    if risk['package'] not in blocked_packages:  # Don't duplicate
                        blocked_packages.append(risk['package'])
                    reasons.append(f"Supply chain risk: {package_risk['description']} ({risk['package']})")
            total_risk_score += supply_chain_result['total_risk_score']

        approved = len(blocked_packages) == 0 and total_risk_score < 0.3

        result = {
            'approved': approved,
            'blocked_packages': blocked_packages,
            'reasons': reasons,
            'total_packages': len(manifest),
            'blocked_count': len(blocked_packages),
            'risk_score': min(total_risk_score, 1.0),
            'namespace_violations': sum(1 for r in reasons if 'Namespace lock' in r),
            'supply_chain_risks': sum(1 for r in reasons if 'Supply chain' in r)
        }

        logger.warning(f"Dependency Sentinel: approved={approved}, blocked={len(blocked_packages)}, risk_score={total_risk_score:.2f}")
        return result