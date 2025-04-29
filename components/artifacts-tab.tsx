"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Bot, FileDown } from "lucide-react"
import { CodeBlock } from "@/components/code-block"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"

// Import sample data
import fridaScript from "@/output/llm/generated_artifacts/diva-beta/finding_4_script.js"
import adbCommand from "@/output/llm/generated_artifacts/diva-beta/finding_4_adb.txt"
import hints from "@/output/llm/generated_artifacts/diva-beta/finding_4_hints.txt"
import runConfig from "@/output/llm/generated_artifacts/diva-beta/run_finding_4.json"

export function ArtifactsTab({ apkName }: { apkName: string }) {
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, you would fetch this data from your API
    // For now, we'll use mock data
    setFindings([
      {
        id: "finding_0",
        title: "Insecure Data Storage - SharedPreferences",
        artifacts: {
          script: fridaScript,
          adb: adbCommand,
          hints: hints,
          config: runConfig,
        },
      },
      {
        id: "finding_1",
        title: "SQL Injection Vulnerability",
        artifacts: {
          script: fridaScript,
          adb: adbCommand,
          hints: hints,
          config: runConfig,
        },
      },
      {
        id: "finding_4",
        title: "Insecure Data Storage - File Storage",
        artifacts: {
          script: fridaScript,
          adb: adbCommand,
          hints: hints,
          config: runConfig,
        },
      },
    ])
    setLoading(false)
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading generated artifacts...</div>
  }

  if (!findings || findings.length === 0) {
    return <div className="flex justify-center p-8">No generated artifacts found.</div>
  }

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div className="flex items-start gap-2">
          <div>
            <h2 className="text-2xl font-bold">Generated Artifacts</h2>
            <p className="text-muted-foreground">AI-generated artifacts for dynamic analysis and fuzzing</p>
          </div>
          <Bot className="h-6 w-6 text-primary" />
        </div>
      </div>

      <Accordion type="single" collapsible className="w-full">
        {findings.map((finding, index) => (
          <AccordionItem key={index} value={`finding-${index}`}>
            <AccordionTrigger className="text-left">
              <div className="flex-1">
                <div className="font-medium">{finding.id}</div>
                <div className="text-sm text-muted-foreground">{finding.title}</div>
              </div>
            </AccordionTrigger>
            <AccordionContent>
              <Tabs defaultValue="frida" className="w-full">
                <TabsList className="grid grid-cols-4 w-full">
                  <TabsTrigger value="frida">Frida Script</TabsTrigger>
                  <TabsTrigger value="adb">ADB Command</TabsTrigger>
                  <TabsTrigger value="hints">Fuzzing Hints</TabsTrigger>
                  <TabsTrigger value="config">Run Configuration</TabsTrigger>
                </TabsList>

                <TabsContent value="frida" className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-medium">Frida Script</h3>
                    <Button variant="outline" size="sm">
                      <FileDown className="h-4 w-4 mr-2" />
                      Download Script
                    </Button>
                  </div>
                  <CodeBlock code={finding.artifacts.script} language="javascript" />
                </TabsContent>

                <TabsContent value="adb" className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-medium">ADB Command</h3>
                    <Button variant="outline" size="sm">
                      <FileDown className="h-4 w-4 mr-2" />
                      Download Command
                    </Button>
                  </div>
                  <CodeBlock code={finding.artifacts.adb} language="bash" />
                </TabsContent>

                <TabsContent value="hints" className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-medium">Fuzzing Hints</h3>
                    <Button variant="outline" size="sm">
                      <FileDown className="h-4 w-4 mr-2" />
                      Download Hints
                    </Button>
                  </div>
                  <CodeBlock code={finding.artifacts.hints} language="text" />
                </TabsContent>

                <TabsContent value="config" className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-medium">Run Configuration</h3>
                    <Button variant="outline" size="sm">
                      <FileDown className="h-4 w-4 mr-2" />
                      Download Config
                    </Button>
                  </div>
                  <CodeBlock code={JSON.stringify(finding.artifacts.config, null, 2)} language="json" />
                </TabsContent>
              </Tabs>
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  )
}
