"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Download } from "lucide-react"
import { CodeBlock } from "@/components/code-block"

// Import sample data
import superResults from "@/output/super/diva-beta/results.json"

export function SuperAnalysisTab({ apkName }: { apkName: string }) {
  const [results, setResults] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, you would fetch this data from your API
    // For now, we'll use the imported sample data
    setResults(superResults)
    setLoading(false)
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading SUPER analysis results...</div>
  }

  if (!results) {
    return <div className="flex justify-center p-8">No SUPER analysis results found.</div>
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
      case "warning":
        return "bg-gray-500"
      default:
        return "bg-gray-500"
    }
  }

  const renderVulnerabilityList = (vulnerabilities: any[], title: string) => {
    if (!vulnerabilities || vulnerabilities.length === 0) return null

    return (
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex justify-between items-center">
            <span>
              {title} ({vulnerabilities.length})
            </span>
            <Badge className={getSeverityColor(title)}>{title}</Badge>
          </CardTitle>
          <CardDescription>Vulnerabilities classified as {title.toLowerCase()} severity</CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            {vulnerabilities.map((vuln, index) => (
              <AccordionItem key={index} value={`${title}-${index}`}>
                <AccordionTrigger className="text-left">
                  <div className="flex-1 mr-4">
                    <div className="font-medium">{vuln.name}</div>
                    <div className="text-sm text-muted-foreground">{vuln.file}</div>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-medium mb-1">Description</h4>
                      <p className="text-sm">{vuln.description}</p>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Vulnerable Code (Line {vuln.line})</h4>
                      <CodeBlock code={vuln.code} language="java" />
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">SUPER Analyzer Results</h2>
          <p className="text-muted-foreground">
            SUPER Android Analyzer detects a range of vulnerabilities, including SQL Injections, XSS vulnerabilities,
            superuser checks, and others, using 37 rules in its initial release, with additional capabilities for
            AndroidManifest.xml and certificate analysis.
          </p>
        </div>
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Report
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Summary</CardTitle>
          <CardDescription>Overview of detected vulnerabilities</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-background p-4 rounded-lg border">
              <div className="text-2xl font-bold">{results.total_vulnerabilities}</div>
              <div className="text-sm text-muted-foreground">Total Vulnerabilities</div>
            </div>
            <div className="bg-background p-4 rounded-lg border">
              <div className="text-2xl font-bold text-red-500">{results.criticals_len}</div>
              <div className="text-sm text-muted-foreground">Critical</div>
            </div>
            <div className="bg-background p-4 rounded-lg border">
              <div className="text-2xl font-bold text-orange-500">{results.highs_len}</div>
              <div className="text-sm text-muted-foreground">High</div>
            </div>
            <div className="bg-background p-4 rounded-lg border">
              <div className="text-2xl font-bold text-yellow-500">{results.mediums_len}</div>
              <div className="text-sm text-muted-foreground">Medium</div>
            </div>
            <div className="bg-background p-4 rounded-lg border">
              <div className="text-2xl font-bold text-blue-500">{results.lows_len}</div>
              <div className="text-sm text-muted-foreground">Low</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="space-y-6">
        {renderVulnerabilityList(results.criticals, "Critical")}
        {renderVulnerabilityList(results.highs, "High")}
        {renderVulnerabilityList(results.mediums, "Medium")}
        {renderVulnerabilityList(results.lows, "Low")}
        {renderVulnerabilityList(results.warnings, "Warning")}
      </div>
    </div>
  )
}
