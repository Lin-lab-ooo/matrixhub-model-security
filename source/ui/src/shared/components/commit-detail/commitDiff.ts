import { html as formatDiffHtml, parse } from 'diff2html'

export const MAX_FILES = 50
const MAX_FILE_DIFF_BYTES = 100_000

const textEncoder = new TextEncoder()

interface CommitDiffRender {
  html: string
  hasTooManyFiles: boolean
}

export function splitCommitDiff(rawDiff: string): string[] {
  return rawDiff.split(/(?=^diff --git )/m).filter(Boolean)
}

export function renderCommitDiff(
  rawDiff: string,
  diffTooBigMessage: string,
  rawDiffLinkText: string,
): CommitDiffRender {
  const fileDiffs = splitCommitDiff(rawDiff)
  const diffJson = fileDiffs.slice(0, MAX_FILES).flatMap((fileDiff, fileIndex) => {
    const parsedDiff = parse(fileDiff)

    // Parsing is cheap; rendering (especially side-by-side line matching) is what
    // blows up on large files. Keep the parser's line counts, drop the blocks so
    // the renderer only emits the placeholder message.
    if (textEncoder.encode(fileDiff).byteLength > MAX_FILE_DIFF_BYTES) {
      const message = `${diffTooBigMessage} <a href="#" class="commit-detail-raw-diff-link" data-commit-raw-diff-link="${fileIndex}">${rawDiffLinkText}</a>`

      for (const file of parsedDiff) {
        file.isTooBig = true
        file.blocks = [{
          header: message,
          lines: [],
          newStartLine: 0,
          oldStartLine: 0,
        }]
      }
    }

    return parsedDiff
  })

  return {
    html: diffJson.length > 0
      ? formatDiffHtml(diffJson, {
          drawFileList: true,
          matching: 'lines',
          outputFormat: 'side-by-side',
        })
      : '',
    hasTooManyFiles: fileDiffs.length > MAX_FILES,
  }
}
