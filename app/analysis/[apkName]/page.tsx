import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AnalysisHeader } from "@/components/analysis-header"
import { SuperAnalysisTab } from "@/components/super-analysis-tab"
import { FlowdroidTab } from "@/components/flowdroid-tab"
import { TriageTab } from "@/components/triage-tab"
import { LLMStaticAnalysisTab } from "@/components/llm-static-analysis-tab"
import { ArtifactsTab } from "@/components/artifacts-tab"
import { FuzzerResultsTab } from "@/components/fuzzer-results-tab"

export default async function AnalysisPage({ params }: { params: { apkName: string } }) {
  const { apkName } = params

  return (
    <div className="container mx-auto py-6">
      <AnalysisHeader apkName={apkName} />

      <Tabs defaultValue="super" className="mt-6">
        <TabsList className="grid grid-cols-6 w-full">
          <TabsTrigger value="super">SUPER Analysis</TabsTrigger>
          <TabsTrigger value="flowdroid">FlowDroid</TabsTrigger>
          <TabsTrigger value="triage">Triage Findings</TabsTrigger>
          <TabsTrigger value="llm-static">LLM Static Analysis</TabsTrigger>
          <TabsTrigger value="artifacts">Generated Artifacts</TabsTrigger>
          <TabsTrigger value="fuzzer">Fuzzer Results</TabsTrigger>
        </TabsList>

        <TabsContent value="super">
          <SuperAnalysisTab apkName={apkName} />
        </TabsContent>

        <TabsContent value="flowdroid">
          <FlowdroidTab apkName={apkName} />
        </TabsContent>

        <TabsContent value="triage">
          <TriageTab apkName={apkName} />
        </TabsContent>

        <TabsContent value="llm-static">
          <LLMStaticAnalysisTab apkName={apkName} />
        </TabsContent>

        <TabsContent value="artifacts">
          <ArtifactsTab apkName={apkName} />
        </TabsContent>

        <TabsContent value="fuzzer">
          <FuzzerResultsTab apkName={apkName} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
