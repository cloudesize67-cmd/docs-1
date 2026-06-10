import { FrontMatter } from "@/types";

export const reconstructMarkdownWithFrontmatter = (
  frontMatter: FrontMatter,
  rawMarkdown: string,
): string => {
  const frontmatterLines: string[] = [];

  if (frontMatter.title) {
    frontmatterLines.push(`title: ${frontMatter.title}`);
  }

  if (frontMatter.description) {
    frontmatterLines.push(`description: ${frontMatter.description}`);
  }

  if (frontmatterLines.length === 0) {
    return rawMarkdown;
  }

  return `---\n${frontmatterLines.join("\n")}\n---\n${rawMarkdown}`;
};

export interface GuideData {
  title: string;
  description: string;
  topic: string;
  date?: string;
  tags?: string[];
  author?: { name: string; avatar?: string; link?: string };
  rawMarkdown: string;
}

export const reconstructGuideMarkdownWithFrontmatter = (
  guide: GuideData,
): string => {
  const lines: string[] = [];
  lines.push(`title: ${guide.title}`);
  lines.push(`description: ${guide.description}`);
  lines.push(`topic: ${guide.topic}`);
  if (guide.date) lines.push(`date: "${guide.date}"`);
  if (guide.tags?.length) {
    lines.push(`tags:`);
    for (const tag of guide.tags) lines.push(`  - ${tag}`);
  }
  if (guide.author) {
    lines.push(`author:`);
    lines.push(`  name: ${guide.author.name}`);
    if (guide.author.avatar) lines.push(`  avatar: ${guide.author.avatar}`);
    if (guide.author.link) lines.push(`  link: ${guide.author.link}`);
  }
  return `---\n${lines.join("\n")}\n---\n${guide.rawMarkdown}`;
};

