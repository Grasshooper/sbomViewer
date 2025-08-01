import React, { useMemo } from 'react';
import { SBOMData } from '../types/sbom';
import { Network, Package, ArrowRight, Info } from 'lucide-react';

interface DependencyGraphProps {
  sbomData: SBOMData;
}

export function DependencyGraph({ sbomData }: DependencyGraphProps) {
  const dependencyStats = useMemo(() => {
    if (!sbomData.dependencies) return { total: 0, connected: 0, isolated: 0 };
    
    const totalComponents = sbomData.components?.length || 0;
    const connectedComponents = new Set<string>();
    
    sbomData.dependencies.forEach(dep => {
      connectedComponents.add(dep.ref);
      dep.dependsOn.forEach(ref => connectedComponents.add(ref));
    });
    
    return {
      total: sbomData.dependencies.length,
      connected: connectedComponents.size,
      isolated: totalComponents - connectedComponents.size,
    };
  }, [sbomData]);

  const topDependencies = useMemo(() => {
    if (!sbomData.dependencies || !sbomData.components) return [];
    
    const dependencyCount = new Map<string, number>();
    
    sbomData.dependencies.forEach(dep => {
      dep.dependsOn.forEach(ref => {
        dependencyCount.set(ref, (dependencyCount.get(ref) || 0) + 1);
      });
    });
    
    return Array.from(dependencyCount.entries())
      .map(([ref, count]) => {
        const component = sbomData.components?.find(c => c['bom-ref'] === ref);
        return { ref, count, component };
      })
      .filter(item => item.component)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [sbomData]);

  const sampleDependencies = useMemo(() => {
    if (!sbomData.dependencies || !sbomData.components) return [];
    
    return sbomData.dependencies
      .slice(0, 20)
      .map(dep => {
        const component = sbomData.components?.find(c => c['bom-ref'] === dep.ref);
        const dependencies = dep.dependsOn
          .map(ref => sbomData.components?.find(c => c['bom-ref'] === ref))
          .filter(Boolean)
          .slice(0, 5);
        
        return { component, dependencies };
      })
      .filter(item => item.component);
  }, [sbomData]);

  return (
    <div className="space-y-8">
      {/* Dependency Statistics */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-6">Dependency Statistics</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <Network className="w-8 h-8 text-blue-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{dependencyStats.total}</p>
            <p className="text-sm text-gray-600">Total Dependencies</p>
          </div>
          
          <div className="text-center p-4 bg-emerald-50 rounded-lg">
            <Package className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{dependencyStats.connected}</p>
            <p className="text-sm text-gray-600">Connected Components</p>
          </div>
          
          <div className="text-center p-4 bg-amber-50 rounded-lg">
            <Package className="w-8 h-8 text-amber-600 mx-auto mb-2" />
            <p className="text-2xl font-bold text-gray-900">{dependencyStats.isolated}</p>
            <p className="text-sm text-gray-600">Isolated Components</p>
          </div>
        </div>
      </div>

      {/* Most Dependent Components */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Most Dependent Components</h3>
        <p className="text-gray-600 mb-6">Components that other components depend on most frequently</p>
        
        <div className="space-y-3">
          {topDependencies.map((item, index) => (
            <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-sm font-bold text-blue-600">{index + 1}</span>
                </div>
                <div>
                  <p className="font-medium text-gray-900">{item.component?.name}</p>
                  <p className="text-sm text-gray-600">{item.component?.version || 'No version'}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-lg font-bold text-blue-600">{item.count}</p>
                <p className="text-sm text-gray-500">dependencies</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Sample Dependency Relationships */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Dependency Relationships</h3>
        <p className="text-gray-600 mb-6">Sample of component dependencies (showing first 20)</p>
        
        <div className="space-y-4">
          {sampleDependencies.map((item, index) => (
            <div key={index} className="p-4 border border-gray-200 rounded-lg">
              <div className="flex items-center gap-3 mb-3">
                <Package className="w-5 h-5 text-blue-600" />
                <div>
                  <p className="font-medium text-gray-900">{item.component?.name}</p>
                  <p className="text-sm text-gray-600">{item.component?.version}</p>
                </div>
              </div>
              
              {item.dependencies.length > 0 ? (
                <div className="ml-8 space-y-2">
                  <div className="flex items-center gap-2 text-sm text-gray-500 mb-2">
                    <ArrowRight className="w-4 h-4" />
                    <span>Depends on:</span>
                  </div>
                  {item.dependencies.map((dep, depIndex) => (
                    <div key={depIndex} className="flex items-center gap-2 p-2 bg-gray-50 rounded text-sm">
                      <Package className="w-4 h-4 text-gray-400" />
                      <span className="font-medium text-gray-700">{dep?.name}</span>
                      {dep?.version && (
                        <span className="text-gray-500">v{dep.version}</span>
                      )}
                    </div>
                  ))}
                  {item.dependencies.length < (sbomData.dependencies?.find(d => d.ref === item.component?.['bom-ref'])?.dependsOn.length || 0) && (
                    <p className="text-xs text-gray-500 ml-6">
                      ... and {(sbomData.dependencies?.find(d => d.ref === item.component?.['bom-ref'])?.dependsOn.length || 0) - item.dependencies.length} more
                    </p>
                  )}
                </div>
              ) : (
                <p className="ml-8 text-sm text-gray-500 italic">No dependencies</p>
              )}
            </div>
          ))}
        </div>
        
        {(sbomData.dependencies?.length || 0) > 20 && (
          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-blue-600" />
              <p className="text-sm text-blue-800">
                Showing 20 of {sbomData.dependencies?.length} total dependency relationships. 
                Full dependency graph visualization would require a specialized graph library.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}