import React, { useMemo } from 'react';
import { Component } from '../types/sbom';
import { Shield, AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react';

interface SecurityOverviewProps {
  components: Component[];
}

export function SecurityOverview({ components }: SecurityOverviewProps) {
  const securityAnalysis = useMemo(() => {
    const analysis = {
      total: components.length,
      withHashes: 0,
      withoutHashes: 0,
      licensedComponents: 0,
      unlicensedComponents: 0,
      outdatedComponents: 0,
    };

    components.forEach(component => {
      if (component.hashes && component.hashes.length > 0) {
        analysis.withHashes++;
      } else {
        analysis.withoutHashes++;
      }

      if (component.licenses && component.licenses.length > 0) {
        analysis.licensedComponents++;
      } else {
        analysis.unlicensedComponents++;
      }

      // Simple heuristic for potentially outdated components
      if (component.version && /^[0-9]+\.[0-9]+/.test(component.version)) {
        const majorVersion = parseInt(component.version.split('.')[0]);
        if (majorVersion < 2) {
          analysis.outdatedComponents++;
        }
      }
    });

    return analysis;
  }, [components]);

  const securityScore = useMemo(() => {
    const hashScore = (securityAnalysis.withHashes / securityAnalysis.total) * 30;
    const licenseScore = (securityAnalysis.licensedComponents / securityAnalysis.total) * 40;
    const versionScore = ((securityAnalysis.total - securityAnalysis.outdatedComponents) / securityAnalysis.total) * 30;
    return Math.round(hashScore + licenseScore + versionScore);
  }, [securityAnalysis]);

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-600';
    if (score >= 60) return 'text-amber-600';
    return 'text-red-600';
  };

  const getScoreIcon = (score: number) => {
    if (score >= 80) return <CheckCircle className="w-8 h-8 text-emerald-600" />;
    if (score >= 60) return <AlertTriangle className="w-8 h-8 text-amber-600" />;
    return <XCircle className="w-8 h-8 text-red-600" />;
  };

  return (
    <div className="space-y-8">
      {/* Security Score */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900">Security Score</h2>
          <div className="flex items-center gap-3">
            {getScoreIcon(securityScore)}
            <span className={`text-3xl font-bold ${getScoreColor(securityScore)}`}>
              {securityScore}/100
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <Shield className="w-8 h-8 text-blue-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{securityAnalysis.withHashes}</p>
            <p className="text-sm text-gray-600">Components with Hashes</p>
          </div>
          
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <CheckCircle className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{securityAnalysis.licensedComponents}</p>
            <p className="text-sm text-gray-600">Licensed Components</p>
          </div>
          
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-amber-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{securityAnalysis.outdatedComponents}</p>
            <p className="text-sm text-gray-600">Potentially Outdated</p>
          </div>
        </div>
      </div>

      {/* Security Issues */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Components without Hashes */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-amber-600" />
            <h3 className="text-lg font-semibold text-gray-900">Components without Hashes</h3>
          </div>
          
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {components
              .filter(c => !c.hashes || c.hashes.length === 0)
              .slice(0, 10)
              .map((component, index) => (
                <div key={index} className="p-3 bg-amber-50 rounded-lg">
                  <p className="font-medium text-gray-900">{component.name}</p>
                  <p className="text-sm text-gray-600">{component.version || 'No version'}</p>
                </div>
              ))}
          </div>
          
          {securityAnalysis.withoutHashes > 10 && (
            <p className="text-sm text-gray-500 mt-3">
              And {securityAnalysis.withoutHashes - 10} more components...
            </p>
          )}
        </div>

        {/* Unlicensed Components */}
        <div className="bg-white rounded-xl shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <XCircle className="w-5 h-5 text-red-600" />
            <h3 className="text-lg font-semibold text-gray-900">Unlicensed Components</h3>
          </div>
          
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {components
              .filter(c => !c.licenses || c.licenses.length === 0)
              .slice(0, 10)
              .map((component, index) => (
                <div key={index} className="p-3 bg-red-50 rounded-lg">
                  <p className="font-medium text-gray-900">{component.name}</p>
                  <p className="text-sm text-gray-600">{component.version || 'No version'}</p>
                </div>
              ))}
          </div>
          
          {securityAnalysis.unlicensedComponents > 10 && (
            <p className="text-sm text-gray-500 mt-3">
              And {securityAnalysis.unlicensedComponents - 10} more components...
            </p>
          )}
        </div>
      </div>

      {/* Recommendations */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-600 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-blue-900 mb-2">Security Recommendations</h3>
            <ul className="space-y-2 text-sm text-blue-800">
              <li>• Ensure all components have integrity hashes for verification</li>
              <li>• Review and document licenses for all components</li>
              <li>• Consider updating potentially outdated components</li>
              <li>• Implement regular security scanning for known vulnerabilities</li>
              <li>• Maintain an inventory of all third-party dependencies</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}