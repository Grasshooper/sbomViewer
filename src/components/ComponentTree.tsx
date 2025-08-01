import React from 'react';
import { Component } from '../types/sbom';
import { Package, Code, Layers, FileText } from 'lucide-react';

interface ComponentTreeProps {
  components: Component[];
  selectedComponent: Component | null;
  onSelectComponent: (component: Component) => void;
}

export function ComponentTree({ components, selectedComponent, onSelectComponent }: ComponentTreeProps) {
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'framework': return <Layers className="w-4 h-4" />;
      case 'library': return <Package className="w-4 h-4" />;
      case 'application': return <Code className="w-4 h-4" />;
      default: return <FileText className="w-4 h-4" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'framework': return 'text-amber-600 bg-amber-50';
      case 'library': return 'text-emerald-600 bg-emerald-50';
      case 'application': return 'text-purple-600 bg-purple-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="space-y-1 p-4">
      {components.map((component) => (
        <button
          key={component['bom-ref']}
          onClick={() => onSelectComponent(component)}
          className={`w-full text-left p-3 rounded-lg transition-colors group ${
            selectedComponent?.['bom-ref'] === component['bom-ref']
              ? 'bg-blue-50 border border-blue-200'
              : 'hover:bg-gray-50'
          }`}
        >
          <div className="flex items-start gap-3">
            <div className={`p-1.5 rounded-md ${getTypeColor(component.type)}`}>
              {getTypeIcon(component.type)}
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-medium text-gray-900 truncate">{component.name}</p>
              <div className="flex items-center gap-2 mt-1">
                {component.version && (
                  <span className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
                    v{component.version}
                  </span>
                )}
                <span className={`text-xs px-2 py-0.5 rounded capitalize ${getTypeColor(component.type)}`}>
                  {component.type}
                </span>
              </div>
            </div>
          </div>
        </button>
      ))}
      
      {components.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No components found</p>
        </div>
      )}
    </div>
  );
}