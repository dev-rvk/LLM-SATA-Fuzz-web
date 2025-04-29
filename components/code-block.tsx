"use client"

import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface CodeBlockProps {
  code: string
  language?: string
  showLineNumbers?: boolean
  className?: string
}

export function CodeBlock({ code, language = "java", showLineNumbers = true, className }: CodeBlockProps) {
  const [copied, setCopied] = useState(false)

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className={cn("relative rounded-md border", className)}>
      <div className="flex items-center justify-between px-4 py-2 border-b bg-muted/50">
        <div className="text-sm text-muted-foreground">{language}</div>
        <Button variant="ghost" size="sm" className="h-8 px-2" onClick={copyToClipboard}>
          {copied ? (
            <>
              <Check className="h-4 w-4 mr-1" />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Copy className="h-4 w-4 mr-1" />
              <span>Copy</span>
            </>
          )}
        </Button>
      </div>
      <pre className={cn("p-4 overflow-x-auto text-sm", showLineNumbers && "pl-12 relative")}>
        {showLineNumbers && (
          <div className="absolute left-0 top-0 pt-4 w-8 text-right text-muted-foreground">
            {code.split("\n").map((_, i) => (
              <div key={i} className="pr-2">
                {i + 1}
              </div>
            ))}
          </div>
        )}
        <code>{code}</code>
      </pre>
    </div>
  )
}
