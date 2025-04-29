"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Download, Bot } from "lucide-react"
import { CodeBlock } from "@/components/code-block"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"

// Import sample data
import staticAnalysisReport from "@/output/llm/static_analysis_report/diva-beta/static_analysis_report.json"

export function LLMStaticAnalysisTab({ apkName }: { apkName: string }) {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, you would fetch this data from your API
    // For now, we'll use the imported sample data
    setFindings(staticAnalysisReport)
    setLoading(false)
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading LLM static analysis results...</div>
  }

  if (!findings || findings.length === 0) {
    return <div className="flex justify-center p-8">No LLM static analysis results found.</div>
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500"
      case "high":
        return "bg-orange-500"
      case "medium":
        return "bg-yellow-500"
      case "low":
        return "bg-blue-500"
      default:
        return "bg-gray-500"
    }
  }

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div className="flex items-start gap-2">
          <div>
            <h2 className="text-2xl font-bold">LLM Static Analysis</h2>
            <p className="text-muted-foreground">AI-enhanced analysis of the triaged findings</p>
          </div>
          <Bot className="h-6 w-6 text-primary" />
        </div>
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Analysis Report
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerability Analysis ({findings.length})</CardTitle>
          <CardDescription>Detailed analysis of each vulnerability by AI</CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            {findings.map((finding, index) => (
              <AccordionItem key={index} value={`finding-${index}`}>
                <AccordionTrigger className="text-left">
                  <div className="flex-1 flex justify-between items-center pr-4">
                    <div>
                      <div className="font-medium">
                        {finding.FindingID}: {finding.VulnerabilityType}
                      </div>
                      <div className="text-sm text-muted-foreground">{finding.VulnerabilityCategory}</div>
                    </div>
                    <Badge className={getSeverityColor(finding.Severity)}>{finding.Severity}</Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-medium mb-1">Description</h4>
                      <p className="text-sm">{finding.VulnerabilityDescription}</p>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Context Analysis</h4>
                      <p className="text-sm">{finding.ContextAnalysis}</p>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Vulnerable Code Lines</h4>
                      {finding.VulnerableCodeLines.map((line: string, lineIndex: number) => (
                        <CodeBlock
                          key={lineIndex}
                          code={line}
                          language="java"
                          showLineNumbers={false}
                          className="mb-2"
                        />
                      ))}
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Suggested Fix</h4>
                      <p className="text-sm">{finding.SuggestedFix}</p>
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
