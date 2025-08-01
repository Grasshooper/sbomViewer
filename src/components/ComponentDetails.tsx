import React from 'react';
import { Component } from '../types/sbom';
import { Package, Calendar, User, Hash, Link2, FileText, Shield, ExternalLink } from 'lucide-react';

interface ComponentDetailsProps {
  component: Component;
}

export function ComponentDetails({ component }: ComponentDetailsProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-blue-50 rounded-lg">
            <Package className="w-6 h-6 text-blue-600" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-semibold text-gray-900">{component.name}</h2>
            <p className="text-gray-600 mt-1">{component.description || 'No description available'}</p>
            <div className="flex items-center gap-4 mt-3">
              {component.version && (
                <span className="inline-flex items-center gap-1 text-sm text-gray-600">
                  <Calendar className="w-4 h-4" />
                  Version {component.version}
                </span>
              )}
              <span className="inline-flex items-center gap-1 text-sm text-gray-600 capitalize">
                <Package className="w-4 h-4" />
                {component.type}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Basic Information */}
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Basic Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {component.author && (
              <div>
                <p className="text-sm font-medium text-gray-500 mb-1">Author</p>
                <p className="text-sm text-gray-900">{component.author}</p>
              </div>
            )}
            {component.publisher && (
              <div>
                <p className="text-sm font-medium text-gray-500 mb-1">Publisher</p>
                <p className="text-sm text-gray-900">{component.publisher}</p>
              </div>
            )}
            {component.copyright && (
              <div>
                <p className="text-sm font-medium text-gray-500 mb-1">Copyright</p>
                <p className="text-sm text-gray-900">{component.copyright}</p>
              </div>
            )}
            {component.purl && (
              <div>
                <p className="text-sm font-medium text-gray-500 mb-1">Package URL</p>
                <p className="text-sm text-gray-900 font-mono break-all">{component.purl}</p>
              </div>
            )}
          </div>
        </div>

        {/* Licenses */}
        {component.licenses && component.licenses.length > 0 && (
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Licenses</h3>
            <div className="space-y-2">
              {component.licenses.map((license, index) => (
                <div key={index} className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
                  <Shield className="w-4 h-4 text-emerald-600" />
                  <span className="text-sm font-medium text-gray-900">
                    {license.license?.name || license.license?.id || 'Unknown License'}
                  </span>
                  {license.license?.url && (
                    <a
                      href={license.license.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hashes */}
        {component.hashes && component.hashes.length > 0 && (
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">File Hashes</h3>
            <div className="space-y-3">
              {component.hashes.map((hash, index) => (
                <div key={index} className="p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-2 mb-2">
                    <Hash className="w-4 h-4 text-gray-600" />
                    <span className="text-sm font-medium text-gray-900">{hash.alg}</span>
                  </div>
                  <p className="text-xs font-mono text-gray-600 break-all">{hash.content}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* External References */}
        {component.externalReferences && component.externalReferences.length > 0 && (
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">External References</h3>
            <div className="space-y-2">
              {component.externalReferences.map((ref, index) => (
                <a
                  key={index}
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <Link2 className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-medium text-gray-900 capitalize">{ref.type}</span>
                  <ExternalLink className="w-4 h-4 text-gray-400 ml-auto" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Properties */}
        {component.properties && component.properties.length > 0 && (
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Properties</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {component.properties.map((prop, index) => (
                <div key={index} className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-sm font-medium text-gray-500 mb-1">{prop.name}</p>
                  <p className="text-sm text-gray-900">{prop.value}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}