"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Download, AlertTriangle, CheckCircle2 } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"

// Import sample data
import fuzzerReport from "@/output/frida_fuzzer/finding_4_fuzzer_results/finding_4_fuzzer_report.json"

export function FuzzerResultsTab({ apkName }: { apkName: string }) {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadFindings = async () => {
      try {
        const findings = await Promise.all(
          Array.from({ length: 7 }, async (_, i) => {
            try {
              const report = await import(
                `@/output/frida_fuzzer/finding_${i}_fuzzer_results/finding_${i}_fuzzer_report.json`
              )
              return {
                id: `finding_${i}`,
                title: `Finding ${i}`,
                report: report.default
              }
            } catch (error) {
              console.warn(`Failed to load finding_${i}:`, error)
              return null
            }
          })
        )

        setFindings(findings.filter(finding => finding !== null))
        setLoading(false)
      } catch (error) {
        console.error("Error loading findings:", error)
        setLoading(false)
      }
    }

    loadFindings()
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading fuzzer results...</div>
  }

  if (!findings || findings.length === 0) {
    return <div className="flex justify-center p-8">No fuzzer results found.</div>
  }

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Fuzzer Results</h2>
          <p className="text-muted-foreground">Results from dynamic analysis and fuzzing</p>
        </div>
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download All Results
        </Button>
      </div>

      <Accordion type="single" collapsible className="w-full">
        {findings.map((finding, index) => (
          <AccordionItem key={index} value={`finding-${index}`}>
            <AccordionTrigger className="text-left">
              <div className="flex-1">
                <div className="font-medium">Finding {index}</div>
                {getVulnerabilityFindings(finding.report).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {getVulnerabilityFindings(finding.report).map((conf, i) => (
                      <Badge key={i} className="bg-red-500">
                        {conf.type}: {conf.strategy}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
            </AccordionTrigger>
            <AccordionContent>
              <Card>
                <CardHeader>
                  <CardTitle>Fuzzing Summary</CardTitle>
                  <CardDescription>Results from {finding.report.length} fuzzing iterations</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-background p-4 rounded-lg border">
                      <div className="text-2xl font-bold">{finding.report.length}</div>
                      <div className="text-sm text-muted-foreground">Total Iterations</div>
                    </div>
                    <div className="bg-background p-4 rounded-lg border">
                      <div className="text-2xl font-bold text-red-500">
                        {finding.report.filter((r: any) => 
                          r.crashed || 
                          (r.detections && r.detections.some((d: { type: string }) => d.type === "Frida Error"))
                        ).length}
                      </div>
                      <div className="text-sm text-muted-foreground">Failed Attempts</div>
                    </div>
                    <div className="bg-background p-4 rounded-lg border">
                      <div className="text-2xl font-bold text-amber-500">
                        {getVulnerabilityFindings(finding.report).length}
                      </div>
                      <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
                    </div>
                    <div className="bg-background p-4 rounded-lg border">
                      <div className="text-2xl font-bold text-blue-500">
                        {finding.report.filter((r: any) => r.ui_errors && r.ui_errors.length > 0).length}
                      </div>
                      <div className="text-sm text-muted-foreground">UI Errors</div>
                    </div>
                  </div>

                  {getVulnerabilityFindings(finding.report).length > 0 && (
                    <div className="mb-6 p-4 border rounded-lg bg-amber-50">
                      <h3 className="text-lg font-medium mb-2">Vulnerabilities Found</h3>
                      <div className="space-y-2">
                        {getVulnerabilityFindings(finding.report).map((vuln, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
                            <div>
                              <div className="font-medium">{vuln.type}</div>
                              <div className="text-sm text-muted-foreground">{vuln.message}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <Accordion type="single" collapsible className="w-full">
                    {finding.report.map((iteration: any, iterIndex: number) => (
                      <AccordionItem key={iterIndex} value={`iteration-${iterIndex}`}>
                        <AccordionTrigger className="text-left">
                          <div className="flex-1 flex justify-between items-center pr-4">
                            <div>
                              <div className="font-medium">Iteration #{iteration.iteration}</div>
                              <div className="text-sm text-muted-foreground">
                                {Object.keys(iteration.inputs_used || {}).length} inputs used
                              </div>
                            </div>
                            {iteration.crashed || 
                              (iteration.ui_errors && iteration.ui_errors.length > 0) || 
                              (iteration.detections && iteration.detections.some((d: { type: string }) => d.type === "Frida Error")) ? (
                              <Badge className="bg-red-500">Failed</Badge>
                            ) : (
                              <Badge className="bg-green-500">Success</Badge>
                            )}
                          </div>
                        </AccordionTrigger>
                        <AccordionContent>
                          <Tabs defaultValue="inputs" className="w-full">
                            <TabsList className="grid grid-cols-3 w-full">
                              <TabsTrigger value="inputs">Inputs</TabsTrigger>
                              <TabsTrigger value="detections">
                                Detections ({iteration.detections?.length || 0})
                              </TabsTrigger>
                              <TabsTrigger value="errors">
                                UI Errors ({iteration.ui_errors?.length || 0})
                              </TabsTrigger>
                            </TabsList>

                            <TabsContent value="inputs" className="space-y-4">
                              <h3 className="text-lg font-medium">Inputs Used</h3>
                              {iteration.inputs_used &&
                                Object.entries(iteration.inputs_used).map(([key, value]: [string, any], i: number) => (
                                  <div key={i} className="border p-2 rounded-md">
                                    <div className="font-medium text-sm">{key}</div>
                                    <div className="text-sm font-mono break-all">{value as string}</div>
                                  </div>
                                ))}
                            </TabsContent>

                            <TabsContent value="detections" className="space-y-4">
                              <h3 className="text-lg font-medium">Detections</h3>
                              {iteration.detections && iteration.detections.length > 0 ? (
                                <div className="border p-3 rounded-md space-y-4">
                                  {Array.from(new Set(iteration.detections.map((d: any) => d.type))).map((type: string, i: number) => {
                                    const typeDetections = iteration.detections.filter((d: any) => d.type === type);
                                    return (
                                      <div key={i} className="flex items-start gap-2">
                                        <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
                                        <div>
                                          <div className="font-medium">{type}</div>
                                          <div className="text-sm mt-1 space-y-1">
                                            {Array.from(new Set(typeDetections.map((d: any) => d.message))).map((message, j) => (
                                              <p key={j}>{message as string}</p>
                                            ))}
                                          </div>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              ) : (
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <CheckCircle2 className="h-5 w-5" />
                                  <span>No detections in this iteration</span>
                                </div>
                              )}
                            </TabsContent>

                            <TabsContent value="errors" className="space-y-4">
                              <h3 className="text-lg font-medium">UI Errors ({iteration.ui_errors?.length || 0})</h3>
                              {iteration.ui_errors && iteration.ui_errors.length > 0 ? (
                                <div className="space-y-2">
                                  {iteration.ui_errors.map((error: any, i: number) => (
                                    <div key={i} className="border p-3 rounded-md">
                                      <div className="flex items-start gap-2">
                                        <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
                                        <div>
                                          <div className="font-medium">
                                            {typeof error === 'object' ? (error.type || 'Unknown Error') : 'Error'}
                                          </div>
                                          <div className="text-sm text-muted-foreground mt-1">
                                            {typeof error === 'object' 
                                              ? (error.message || JSON.stringify(error, null, 2))
                                              : error.toString()}
                                          </div>
                                          {typeof error === 'object' && error.stackTrace && (
                                            <pre className="text-xs bg-slate-50 p-2 mt-2 rounded overflow-auto">
                                              {error.stackTrace}
                                            </pre>
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <CheckCircle2 className="h-5 w-5" />
                                  <span>No UI errors in this iteration</span>
                                </div>
                              )}
                            </TabsContent>
                          </Tabs>
                        </AccordionContent>
                      </AccordionItem>
                    ))}
                  </Accordion>
                </CardContent>
              </Card>
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  )
}

// Add this helper function at the top level
const getVulnerabilityFindings = (report: any[]) => {
  // First, collect all detections that aren't Frida errors
  const allDetections = report.flatMap((iteration) => 
    iteration.detections?.filter((d: any) => {
      // Filter out Frida errors
      if (d.type === "Frida Error") return false;
      
      // Check for either "Vulnerability Confirmed" or other significant detections
      return d.message?.toLowerCase().includes('vulnerability confirmed') || 
             d.type?.toLowerCase().includes('vulnerability') ||
             d.type?.toLowerCase().includes('sensitive data') ||
             d.type?.toLowerCase().includes('security');
    }) || []
  );

  // Group by type and strategy to remove duplicates
  const groupedByTypeAndStrategy = allDetections.reduce((acc: any, detection: any) => {
    const key = `${detection.type}-${detection.strategy}`;
    if (!acc[key]) {
      acc[key] = {
        type: detection.type,
        strategy: detection.strategy,
        message: detection.message
      };
    }
    return acc;
  }, {});

  // Convert back to array
  return Object.values(groupedByTypeAndStrategy);
};
