"""Checks for the actual learning mechanism and evaluation separation."""
import unittest
import torch
from experiment import PersonalAdapter, TinyModel, cka, digest, prompts


class LearningTests(unittest.TestCase):
    def test_disjoint_prompt_combinations(self):
        train,_=prompts(True,"train");test,_=prompts(True,"test")
        self.assertFalse(set(map(tuple,train.tolist())) & set(map(tuple,test.tolist())))
        self.assertEqual(len(train),288);self.assertEqual(len(test),96)

    def test_adapter_gradient_and_base_freeze(self):
        torch.manual_seed(44);base=TinyModel().eval()
        for p in base.parameters():p.requires_grad_(False)
        before=digest(base);adapter=PersonalAdapter()
        x,t=prompts(True,"train")
        with torch.no_grad():h=base.encode(x[:32])
        loss=torch.nn.functional.cross_entropy(base.head(adapter(h)),(t[:32]+1)%4)
        loss.backward()
        self.assertGreater(float(adapter.b.grad.abs().sum()),0)
        self.assertTrue(all(p.grad is None for p in base.parameters()))
        self.assertEqual(before,digest(base))

    def test_leave_one_out_reward_gradient_matches_expected_reward(self):
        torch.manual_seed(63)
        logits=torch.tensor([0.3,-0.1,0.4,0.0],requires_grad=True)
        dist=torch.distributions.Categorical(logits=logits)
        actions=dist.sample((4,50000))
        rewards=(actions==2).float()
        baseline=(rewards.sum(0,keepdim=True)-rewards)/3
        estimate=(dist.log_prob(actions)*(rewards-baseline)).mean()
        sampled=torch.autograd.grad(estimate,logits)[0]
        exact=torch.autograd.grad(logits.softmax(0)[2],logits)[0]
        self.assertTrue(torch.allclose(sampled,exact,atol=0.003), (sampled,exact))

    def test_similarity_can_ignore_output_permutation(self):
        torch.manual_seed(1);h=torch.randn(100,8);pred=torch.randn(100,4).argmax(-1)
        self.assertAlmostEqual(cka(h,h),1.0,places=5)
        self.assertEqual(int((pred==(pred+1)%4).sum()),0)


if __name__=="__main__":unittest.main(verbosity=2)
