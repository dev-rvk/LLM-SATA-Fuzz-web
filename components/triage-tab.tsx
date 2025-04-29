"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Download } from "lucide-react"
import { CodeBlock } from "@/components/code-block"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"

// Import sample data
import triagedFindings from "@/output/triage/diva-beta/triaged_findings.json"

export function TriageTab({ apkName }: { apkName: string }) {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, you would fetch this data from your API
    // For now, we'll use the imported sample data
    setFindings(triagedFindings)
    setLoading(false)
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading triaged findings...</div>
  }

  if (!findings || findings.length === 0) {
    return <div className="flex justify-center p-8">No triaged findings available.</div>
  }

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Triaged Findings</h2>
          <p className="text-muted-foreground">
            Triaged findings from FlowDroid (functions) adding their methods from the source code.
          </p>
        </div>
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Triage Report
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings ({findings.length})</CardTitle>
          <CardDescription>Triaged findings from FlowDroid analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            {findings.map((finding, index) => (
              <AccordionItem key={index} value={`finding-${index}`}>
                <AccordionTrigger className="text-left">
                  <div className="flex-1">
                    <div className="font-medium">
                      Finding #{index + 1}: {finding.FindingID}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      <Badge variant="outline">{finding.DynamicStrategy}</Badge>
                    </div>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-medium mb-1">Sink</h4>
                      <div className="space-y-2">
                        <div>
                          <span className="text-xs font-medium">Method: </span>
                          <span className="text-xs">{finding.Sink.Method}</span>
                        </div>
                        <div>
                          <span className="text-xs font-medium">Statement: </span>
                          <span className="text-xs">{finding.Sink.Statement}</span>
                        </div>
                        <div>
                          <span className="text-xs font-medium">Definition: </span>
                          <span className="text-xs">{finding.Sink.Definition}</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Sources ({finding.Sources.length})</h4>
                      {finding.Sources.map((source: any, sourceIndex: number) => (
                        <div key={sourceIndex} className="border p-2 rounded-md mb-2">
                          <div className="space-y-1">
                            <div>
                              <span className="text-xs font-medium">Method: </span>
                              <span className="text-xs">{source.Method}</span>
                            </div>
                            <div>
                              <span className="text-xs font-medium">Statement: </span>
                              <span className="text-xs">{source.Statement}</span>
                            </div>
                            <div>
                              <span className="text-xs font-medium">Definition: </span>
                              <span className="text-xs">{source.Definition}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Source Code</h4>
                      <CodeBlock code={finding.MethodSourceCode} language="java" />
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>
    </div>
  )
}
