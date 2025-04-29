import { ArrowLeft, Download } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"

export function AnalysisHeader({ apkName }: { apkName: string }) {
  return (
    <div className="flex flex-col space-y-4 md:flex-row md:justify-between md:items-center">
      <div>
        <Link href="/" className="flex items-center text-sm text-muted-foreground hover:text-foreground mb-2">
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to Upload
        </Link>
        <h1 className="text-3xl font-bold">{apkName}</h1>
        <p className="text-muted-foreground">Analysis Results</p>
      </div>

      <div className="flex space-x-2">
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download Full Report
        </Button>
      </div>
    </div>
  )
}
