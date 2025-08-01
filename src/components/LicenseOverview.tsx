import React, { useMemo } from 'react';
import { Component } from '../types/sbom';
import { FileText, Shield, AlertTriangle, Info } from 'lucide-react';

interface LicenseOverviewProps {
  components: Component[];
}

export function LicenseOverview({ components }: LicenseOverviewProps) {
  const licenseAnalysis = useMemo(() => {
    const licenseMap = new Map<string, { count: number; components: Component[] }>();
    const unlicensed: Component[] = [];

    components.forEach(component => {
      if (!component.licenses || component.licenses.length === 0) {
        unlicensed.push(component);
      } else {
        component.licenses.forEach(license => {
          const licenseName = license.license?.name || license.license?.id || 'Unknown License';
          const existing = licenseMap.get(licenseName);
          if (existing) {
            existing.count++;
            existing.components.push(component);
          } else {
            licenseMap.set(licenseName, { count: 1, components: [component] });
          }
        });
      }
    });

    return {
      licenses: Array.from(licenseMap.entries()).map(([name, data]) => ({
        name,
        count: data.count,
        components: data.components,
      })).sort((a, b) => b.count - a.count),
      unlicensed,
    };
  }, [components]);

  const getLicenseRiskLevel = (licenseName: string) => {
    const copyleftLicenses = ['GPL', 'AGPL', 'LGPL'];
    const permissiveLicenses = ['MIT', 'Apache', 'BSD'];
    
    if (copyleftLicenses.some(cl => licenseName.toUpperCase().includes(cl))) {
      return { level: 'high', color: 'red', label: 'Copyleft' };
    }
    if (permissiveLicenses.some(pl => licenseName.toUpperCase().includes(pl))) {
      return { level: 'low', color: 'emerald', label: 'Permissive' };
    }
    return { level: 'medium', color: 'amber', label: 'Review Required' };
  };

  return (
    <div className="space-y-8">
      {/* License Distribution */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-6">License Distribution</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="text-center p-4 bg-emerald-50 rounded-lg">
            <Shield className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{licenseAnalysis.licenses.length}</p>
            <p className="text-sm text-gray-600">Unique Licenses</p>
          </div>
          
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <FileText className="w-8 h-8 text-blue-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">
              {components.length - licenseAnalysis.unlicensed.length}
            </p>
            <p className="text-sm text-gray-600">Licensed Components</p>
          </div>
          
          <div className="text-center p-4 bg-red-50 rounded-lg">
            <AlertTriangle className="w-8 h-8 text-red-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{licenseAnalysis.unlicensed.length}</p>
            <p className="text-sm text-gray-600">Unlicensed Components</p>
          </div>
        </div>

        {/* License List */}
        <div className="space-y-3">
          {licenseAnalysis.licenses.map((license, index) => {
            const risk = getLicenseRiskLevel(license.name);
            return (
              <div key={index} className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full bg-${risk.color}-500`}></div>
                    <div>
                      <p className="font-medium text-gray-900">{license.name}</p>
                      <p className="text-sm text-gray-600">{license.count} components</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 text-xs font-medium bg-${risk.color}-100 text-${risk.color}-800 rounded`}>
                      {risk.label}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Unlicensed Components */}
      {licenseAnalysis.unlicensed.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            <h3 className="text-lg font-semibold text-gray-900">Unlicensed Components</h3>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {licenseAnalysis.unlicensed.slice(0, 12).map((component, index) => (
              <div key={index} className="p-4 bg-red-50 border border-red-200 rounded-lg">
                <p className="font-medium text-gray-900">{component.name}</p>
                <p className="text-sm text-gray-600">{component.version || 'No version'}</p>
                <span className="inline-block mt-2 text-xs px-2 py-1 bg-red-100 text-red-800 rounded capitalize">
                  {component.type}
                </span>
              </div>
            ))}
          </div>
          
          {licenseAnalysis.unlicensed.length > 12 && (
            <p className="text-sm text-gray-500 mt-4">
              And {licenseAnalysis.unlicensed.length - 12} more unlicensed components...
            </p>
          )}
        </div>
      )}

      {/* Compliance Guidelines */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-600 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-blue-900 mb-2">License Compliance Guidelines</h3>
            <ul className="space-y-2 text-sm text-blue-800">
              <li>• <strong>Permissive licenses (MIT, Apache, BSD):</strong> Generally safe for commercial use</li>
              <li>• <strong>Copyleft licenses (GPL, AGPL):</strong> Require source code disclosure</li>
              <li>• <strong>LGPL licenses:</strong> Allow linking without full disclosure requirements</li>
              <li>• <strong>Unlicensed components:</strong> Require legal review before use</li>
              <li>• <strong>Custom licenses:</strong> Need individual assessment</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}