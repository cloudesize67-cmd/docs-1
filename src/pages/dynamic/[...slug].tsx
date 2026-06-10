import {
  Banner,
  PriorityBoardingBanner,
  DeprecationBanner,
} from "@/components/banner";
import { Collapse } from "@/components/collapse";
import { Pre, CodeBlock, CodeTab } from "@/components/code-block";
import { GraphQLCodeTabs } from "@/components/graphql-code-tabs";
import { Card, CardGrid } from "@/components/card";
import { Frame } from "@/components/frame";
import { Steps, Step } from "@/components/steps";
import {
  Tree,
  TreeNode,
  TreeNodeTrigger,
  TreeNodeContent,
  TreeExpander,
  TreeIcon,
  TreeLabel,
} from "@/components/tree";
import { FileTree } from "@/components/file-tree";
import { Tooltip } from "@/components/tooltip";
import Layout from "@/mdxLayouts/index";
import { allPages, Page } from "content-collections";
import { useMDXComponent } from "@content-collections/mdx/react";
import Link from "next/link";
import { Image } from "@/components/image";
import { InlineCode } from "@/components/inline-code";
import { H2, H3, H4 } from "@/components/header";
import { Anchor } from "@/components/anchor";
import { GetServerSidePropsContext } from "next";
import { TallyButton } from "@/components/tally-button";
import {
  reconstructMarkdownWithFrontmatter,
  reconstructGuideMarkdownWithFrontmatter,
} from "@/utils/markdown";
import { allGuides } from "content-collections";

const components: Record<string, React.ElementType> = {
  Collapse,
  Image,
  Banner,
  Link,
  PriorityBoardingBanner,
  DeprecationBanner,
  a: Anchor,
  h2: H2,
  h3: H3,
  h4: H4,
  TallyButton,
  pre: Pre,
  code: InlineCode,
  CodeBlock,
  CodeTab,
  GraphQLCodeTabs,
  Card,
  CardGrid,
  Frame,
  Steps,
  Step,
  Tree,
  TreeNode,
  TreeNodeTrigger,
  TreeNodeContent,
  TreeExpander,
  TreeIcon,
  TreeLabel,
  FileTree,
  Tooltip,
};

export default function PostPage({
  page,
  rawMarkdown,
}: {
  page: Page;
  rawMarkdown: string;
}) {
  const MDXContent = useMDXComponent(page.body.code);

  return (
    <Layout
      frontMatter={{
        title: page.title,
        description: page.description,
        url: page.url,
        lastModified: page.lastModified,
      }}
      rawMarkdown={rawMarkdown}
    >
      <MDXContent components={components} />
    </Layout>
  );
}

export const getServerSideProps = async (
  context: GetServerSidePropsContext,
) => {
  const { slug } = context.params as { slug: string[] };
  const slugPath = `/${slug.join("/")}`;
  const page = allPages.find(p => p.url === slugPath);

  // Return raw markdown if format=md — supports both docs pages and guides
  if (context.query.format === "md") {
    const guide = page ? null : allGuides.find(g => g.url === slugPath);
    if (!page && !guide) {
      return { notFound: true };
    }
    const markdown = guide
      ? reconstructGuideMarkdownWithFrontmatter({
          title: guide.title,
          description: guide.description,
          topic: guide.topic,
          date: guide.date,
          tags: guide.tags,
          author: guide.author,
          rawMarkdown: guide.body.raw,
        })
      : reconstructMarkdownWithFrontmatter(
          { title: page!.title, description: page!.description, url: page!.url },
          page!.body.raw,
        );
    context.res.setHeader("Content-Type", "text/markdown; charset=utf-8");
    context.res.write(markdown);
    context.res.end();
    return { props: {} };
  }

  if (!page) {
    return {
      notFound: true,
    };
  }

  return {
    props: {
      page,
      rawMarkdown: page.body.raw,
    },
  };
};
