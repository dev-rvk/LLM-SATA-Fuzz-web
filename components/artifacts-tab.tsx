"use client"

import { Button } from "@/components/ui/button"
import { Bot, FileDown } from "lucide-react"
import { CodeBlock } from "@/components/code-block"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"

// Define finding titles
const FINDING_TITLES = [
  "Insecure Data Storage - SharedPreferences",
  "Insecure Data Storage - SQLite",
  "Input Validation - SQL Injection",
  "Access Control - Activity Access",
  "Input Validation - XSS",
  "Access Control - Local Storage",
  "Input Validation - Code Injection"
]

// Dynamic imports for findings
const importFindingArtifacts = (index: number) => {
  const artifacts = {
    script: require(`@/output/llm/generated_artifacts/diva-beta/finding_${index}_script.js`),
    adb: require(`@/output/llm/generated_artifacts/diva-beta/finding_${index}_adb.txt`),
    hints: require(`@/output/llm/generated_artifacts/diva-beta/finding_${index}_hints.txt`),
    config: require(`@/output/llm/generated_artifacts/diva-beta/run_finding_${index}.json`)
  }

  // Helper function to parse JSON string or return the original if it's already an object
  const parseJSON = (json: any) => {
    if (typeof json === 'string') {
      try {
        return JSON.parse(json);
      } catch (e) {
        return json;
      }
    }
    return json;
  };

  return {
    script: artifacts.script?.default || artifacts.script || '',
    adb: artifacts.adb?.default || artifacts.adb || '',
    hints: artifacts.hints?.default || artifacts.hints || '',
    config: parseJSON(artifacts.config?.default || artifacts.config)
  }
}

export function ArtifactsTab({ apkName }: { apkName: string }) {
  const findings = Array.from({ length: 7 }, (_, i) => ({
    id: `finding_${i}`,
    artifacts: importFindingArtifacts(i)
  }))

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
